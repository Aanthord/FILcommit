// filcommit: HITC-friendly "commit-delete" for Linux filesystems.
//
// Hardened implementation:
//   - Pure Go syscalls via golang.org/x/sys/unix (no CGO)
//   - O_DIRECT support for page-cache bypass
//   - mlock() to prevent sensitive data from swap
//   - Secure buffer zeroing with memory barriers
//   - getrandom(2) for entropy
//   - Proper fsync/fdatasync/syncfs semantics
//   - fallocate PUNCH_HOLE for sparse-aware wipe
//   - posix_fadvise hints for sequential I/O
//   - Full Stat_t extraction (inode, uid, gid, timestamps)
//
// Build: go build -o filcommit .
//
// Example:
//   sudo ./filcommit -path ./data.bin -journal ./.filcommit.journal \
//     -wipe=random -direct=true -mlock=true \
//     -zipkin_url http://localhost:9411/api/v2/spans
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	journalMagic = "FILCMT02" // 8 bytes (v2 for hardened)
	recMagic     = "REC1"     // 4 bytes
	version      = uint32(2)

	// Alignment for O_DIRECT (512 typical, 4096 safe for all)
	directAlign = 4096
)

// ============================================================================
// Secure memory primitives
// ============================================================================

// secureZero wipes a byte slice with a memory barrier to prevent optimization.
// Uses volatile-equivalent pattern to defeat dead-store elimination.
func secureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Memory barrier: prevent compiler from optimizing away the zeroing.
	// atomic.StoreUint32 forces a sync point.
	var dummy uint32
	atomic.StoreUint32(&dummy, 0)
	runtime.KeepAlive(b)
}

// secureAlloc allocates a byte slice and optionally mlocks it.
func secureAlloc(size int, mlock bool) ([]byte, error) {
	// Allocate page-aligned for O_DIRECT compatibility
	aligned := (size + directAlign - 1) &^ (directAlign - 1)
	buf := make([]byte, aligned)

	if mlock {
		// mlock to prevent swapping sensitive data
		if err := unix.Mlock(buf); err != nil {
			// Non-fatal: may lack CAP_IPC_LOCK or hit RLIMIT_MEMLOCK
			log.Printf("warn: mlock failed (size=%d): %v", aligned, err)
		}
	}
	return buf[:size], nil
}

// secureFree zeros and optionally munlocks a buffer.
func secureFree(b []byte, wasLocked bool) {
	secureZero(b)
	if wasLocked {
		// Best effort munlock; slice may have been reallocated
		_ = unix.Munlock(b)
	}
}

// ============================================================================
// Entropy (getrandom syscall)
// ============================================================================

// cryptoRandFill uses getrandom(2) directly for kernel entropy.
func cryptoRandFill(b []byte) error {
	// GRND_NONBLOCK: fail if entropy pool not ready (boot edge case)
	// For production wipe, we want blocking to ensure quality entropy.
	n, err := unix.Getrandom(b, 0) // 0 = blocking, high-quality
	if err != nil {
		return fmt.Errorf("getrandom: %w", err)
	}
	if n != len(b) {
		return fmt.Errorf("getrandom: short read %d/%d", n, len(b))
	}
	return nil
}

// ============================================================================
// Privilege checking (STRICT - fail hard on violation)
// ============================================================================

// requirePriv checks if we have privileges for the requested operation.
// Returns nil if OK, error if not. Caller should FATAL on error when
// the operation was explicitly requested.
func requirePriv(operation string) error {
	// CAP_LINUX_IMMUTABLE (cap 9) is the precise capability needed,
	// but checking euid==0 is the common case. For production, use
	// golang.org/x/sys/unix.Prctl with PR_CAPBSET_READ.
	if unix.Geteuid() != 0 {
		return fmt.Errorf("%s: requires root or CAP_LINUX_IMMUTABLE (euid=%d)", operation, unix.Geteuid())
	}
	return nil
}

// ============================================================================
// Linux FS flags via ioctl (pure Go)
// ============================================================================

const (
	// From linux/fs.h
	FS_IOC_GETFLAGS = 0x80086601
	FS_IOC_SETFLAGS = 0x40086602

	FS_APPEND_FL    = 0x00000020
	FS_IMMUTABLE_FL = 0x00000010
	FS_NOATIME_FL   = 0x00000080
	FS_SYNC_FL      = 0x00000008
)

func getFSFlags(fd int) (int32, error) {
	var flags int32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(FS_IOC_GETFLAGS), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return 0, fmt.Errorf("FS_IOC_GETFLAGS: %w", errno)
	}
	return flags, nil
}

func setFSFlags(fd int, flags int32) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(FS_IOC_SETFLAGS), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return fmt.Errorf("FS_IOC_SETFLAGS: %w", errno)
	}
	return nil
}

func modifyFSFlags(fd int, set, clear int32) error {
	flags, err := getFSFlags(fd)
	if err != nil {
		return err
	}
	flags = (flags | set) &^ clear
	return setFSFlags(fd, flags)
}

// ============================================================================
// File identity from Stat_t
// ============================================================================

type FileIdentity struct {
	Dev     uint64
	Inode   uint64
	Nlink   uint64
	Mode    uint32
	UID     uint32
	GID     uint32
	Rdev    uint64
	Size    int64
	Blksize int64
	Blocks  int64
	Atime   unix.Timespec
	Mtime   unix.Timespec
	Ctime   unix.Timespec
}

func getFileIdentity(fd int) (FileIdentity, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return FileIdentity{}, fmt.Errorf("fstat: %w", err)
	}
	return FileIdentity{
		Dev:     st.Dev,
		Inode:   st.Ino,
		Nlink:   st.Nlink,
		Mode:    st.Mode,
		UID:     st.Uid,
		GID:     st.Gid,
		Rdev:    st.Rdev,
		Size:    st.Size,
		Blksize: st.Blksize,
		Blocks:  st.Blocks,
		Atime:   st.Atim,
		Mtime:   st.Mtim,
		Ctime:   st.Ctim,
	}, nil
}

// ============================================================================
// Sync primitives
// ============================================================================

// syncFile performs fdatasync (data only) or fsync (data + metadata).
func syncFile(fd int, metadataToo bool) error {
	if metadataToo {
		return unix.Fsync(fd)
	}
	return unix.Fdatasync(fd)
}

// syncFilesystem syncs the entire filesystem containing fd.
func syncFilesystem(fd int) error {
	return unix.Syncfs(fd)
}

// adviseSequential hints to kernel that we'll access sequentially.
func adviseSequential(fd int, offset, length int64) error {
	return unix.Fadvise(fd, offset, length, unix.FADV_SEQUENTIAL)
}

// adviseDontNeed hints kernel to drop pages from cache.
func adviseDontNeed(fd int, offset, length int64) error {
	return unix.Fadvise(fd, offset, length, unix.FADV_DONTNEED)
}

// ============================================================================
// Wipe strategies
// ============================================================================

type WipeMode int

const (
	WipeModeZero WipeMode = iota
	WipeModeRandom
	WipeModePunchHole // fallocate PUNCH_HOLE (sparse-aware)
	WipeModePattern   // DoD 5220.22-M style (overkill but available)
)

func (m WipeMode) String() string {
	switch m {
	case WipeModeZero:
		return "zero"
	case WipeModeRandom:
		return "random"
	case WipeModePunchHole:
		return "punch"
	case WipeModePattern:
		return "pattern"
	default:
		return fmt.Sprintf("unknown(%d)", int(m))
	}
}

func ParseWipeMode(s string) (WipeMode, error) {
	switch s {
	case "zero":
		return WipeModeZero, nil
	case "random":
		return WipeModeRandom, nil
	case "punch":
		return WipeModePunchHole, nil
	case "pattern":
		return WipeModePattern, nil
	default:
		return 0, fmt.Errorf("unknown wipe mode: %s (use zero|random|punch|pattern)", s)
	}
}

// WipeConfig controls wipe behavior.
type WipeConfig struct {
	Mode      WipeMode
	ChunkSize int
	Passes    int  // For pattern mode
	UseDirect bool // O_DIRECT bypass page cache
	UseMlock  bool // mlock wipe buffer
	SyncEvery int  // fdatasync every N chunks (0 = end only)
	DropCache bool // FADV_DONTNEED after wipe
}

func DefaultWipeConfig() WipeConfig {
	return WipeConfig{
		Mode:      WipeModeZero,
		ChunkSize: 1 << 20, // 1MB
		Passes:    1,
		UseDirect: false,
		UseMlock:  true,
		SyncEvery: 0,
		DropCache: true,
	}
}

// ============================================================================
// Wipe implementation
// ============================================================================

// alignedPrefix returns the largest offset <= size that is aligned to align.
func alignedPrefix(size int64, align int64) int64 {
	return size &^ (align - 1)
}

func wipeFile(ctx context.Context, tr *tracer, path string, size int64, cfg WipeConfig) error {
	ctx, sp := tr.Start(ctx, "file.wipe", map[string]string{
		"mode":   cfg.Mode.String(),
		"size":   fmt.Sprintf("%d", size),
		"chunk":  fmt.Sprintf("%d", cfg.ChunkSize),
		"direct": fmt.Sprintf("%t", cfg.UseDirect),
	})
	defer sp.End()

	if size == 0 {
		return nil
	}

	// Punch-hole mode uses fallocate, not buffer writes
	if cfg.Mode == WipeModePunchHole {
		return wipePunchHole(ctx, tr, path, size)
	}

	// O_DIRECT tail problem: direct I/O requires aligned size.
	// Strategy: wipe [0, alignedEnd) with O_DIRECT, [alignedEnd, size) buffered.
	alignedEnd := size
	if cfg.UseDirect {
		alignedEnd = alignedPrefix(size, int64(directAlign))
	}
	hasTail := alignedEnd < size

	// Allocate (possibly mlocked) buffer
	chunkSize := cfg.ChunkSize
	if cfg.UseDirect && chunkSize%directAlign != 0 {
		chunkSize = (chunkSize + directAlign - 1) &^ (directAlign - 1)
	}

	buf, err := secureAlloc(chunkSize, cfg.UseMlock)
	if err != nil {
		return err
	}
	defer secureFree(buf, cfg.UseMlock)

	// Phase 1: O_DIRECT for aligned region (if any)
	if alignedEnd > 0 {
		flags := unix.O_WRONLY
		if cfg.UseDirect {
			flags |= unix.O_DIRECT
		}

		fd, err := unix.Open(path, flags, 0)
		if err != nil {
			return fmt.Errorf("open for wipe (direct): %w", err)
		}

		_ = adviseSequential(fd, 0, alignedEnd)

		for pass := 0; pass < cfg.Passes; pass++ {
			if err := wipeRegion(ctx, tr, fd, 0, alignedEnd, buf, cfg, pass); err != nil {
				unix.Close(fd)
				return fmt.Errorf("wipe aligned region pass %d: %w", pass, err)
			}
		}

		if err := syncFile(fd, false); err != nil {
			unix.Close(fd)
			return fmt.Errorf("fdatasync (direct): %w", err)
		}

		if cfg.DropCache {
			_ = adviseDontNeed(fd, 0, alignedEnd)
		}

		unix.Close(fd)
	}

	// Phase 2: Buffered I/O for tail (if any)
	if hasTail {
		tailSize := size - alignedEnd

		fd, err := unix.Open(path, unix.O_WRONLY, 0) // no O_DIRECT
		if err != nil {
			return fmt.Errorf("open for wipe (tail): %w", err)
		}

		// Smaller buffer for tail - no alignment needed
		tailBuf := buf
		if int64(len(tailBuf)) > tailSize {
			tailBuf = tailBuf[:tailSize]
		}

		for pass := 0; pass < cfg.Passes; pass++ {
			if err := wipeRegion(ctx, tr, fd, alignedEnd, size, tailBuf, cfg, pass); err != nil {
				unix.Close(fd)
				return fmt.Errorf("wipe tail pass %d: %w", pass, err)
			}
		}

		if err := syncFile(fd, true); err != nil {
			unix.Close(fd)
			return fmt.Errorf("fsync (tail): %w", err)
		}

		unix.Close(fd)
	}

	return nil
}

// wipeRegion wipes [start, end) of an already-open fd.
func wipeRegion(ctx context.Context, tr *tracer, fd int, start, end int64, buf []byte, cfg WipeConfig, pass int) error {
	// Fill function based on mode
	var fill func([]byte, int) error
	switch cfg.Mode {
	case WipeModeZero:
		fill = func(b []byte, _ int) error {
			for i := range b {
				b[i] = 0
			}
			return nil
		}
	case WipeModeRandom:
		fill = func(b []byte, _ int) error {
			return cryptoRandFill(b)
		}
	case WipeModePattern:
		// DoD 5220.22-M: pass 0 = 0x00, pass 1 = 0xFF, pass 2 = random
		patterns := []byte{0x00, 0xFF}
		fill = func(b []byte, p int) error {
			if p < len(patterns) {
				for i := range b {
					b[i] = patterns[p]
				}
				return nil
			}
			return cryptoRandFill(b)
		}
	default:
		return fmt.Errorf("unsupported wipe mode: %v", cfg.Mode)
	}

	offset := start
	chunks := 0
	for offset < end {
		n := int64(len(buf))
		if offset+n > end {
			n = end - offset
		}

		if err := fill(buf[:n], pass); err != nil {
			return fmt.Errorf("fill: %w", err)
		}

		written, err := unix.Pwrite(fd, buf[:n], offset)
		if err != nil {
			return fmt.Errorf("pwrite at %d: %w", offset, err)
		}
		if int64(written) != n {
			return fmt.Errorf("short write: %d/%d at offset %d", written, n, offset)
		}

		offset += n
		chunks++

		// Periodic sync if configured
		if cfg.SyncEvery > 0 && chunks%cfg.SyncEvery == 0 {
			if err := syncFile(fd, false); err != nil {
				return fmt.Errorf("fdatasync: %w", err)
			}
		}
	}

	return nil
}

func wipePunchHole(ctx context.Context, tr *tracer, path string, size int64) error {
	ctx, sp := tr.Start(ctx, "file.punch_hole", map[string]string{"size": fmt.Sprintf("%d", size)})
	defer sp.End()

	fd, err := unix.Open(path, unix.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer unix.Close(fd)

	// FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE
	// Deallocates blocks, keeps file size (sparse hole)
	const (
		FALLOC_FL_KEEP_SIZE  = 0x01
		FALLOC_FL_PUNCH_HOLE = 0x02
	)

	err = unix.Fallocate(fd, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE, 0, size)
	if err != nil {
		return fmt.Errorf("fallocate PUNCH_HOLE: %w", err)
	}

	return syncFile(fd, true)
}

// ============================================================================
// SHA256 with O_DIRECT option (dual-fd for tail safety)
// ============================================================================

func sha256File(ctx context.Context, tr *tracer, path string, useDirect bool, useMlock bool) ([32]byte, error) {
	ctx, sp := tr.Start(ctx, "file.sha256", map[string]string{
		"path":   path,
		"direct": fmt.Sprintf("%t", useDirect),
	})
	defer sp.End()

	var out [32]byte

	// Get file size first (normal open)
	stFd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		return out, fmt.Errorf("open for stat: %w", err)
	}
	id, err := getFileIdentity(stFd)
	unix.Close(stFd)
	if err != nil {
		return out, err
	}
	size := id.Size

	if size == 0 {
		// Empty file - just return hash of nothing
		h := sha256.New()
		copy(out[:], h.Sum(nil))
		return out, nil
	}

	// O_DIRECT tail problem: read [0, alignedEnd) with O_DIRECT, [alignedEnd, size) buffered
	alignedEnd := size
	if useDirect {
		alignedEnd = alignedPrefix(size, int64(directAlign))
	}
	hasTail := alignedEnd < size

	// Allocate read buffer
	bufSize := 1 << 20 // 1MB
	if useDirect && bufSize%directAlign != 0 {
		bufSize = (bufSize + directAlign - 1) &^ (directAlign - 1)
	}
	buf, err := secureAlloc(bufSize, useMlock)
	if err != nil {
		return out, err
	}
	defer secureFree(buf, useMlock)

	h := sha256.New()

	// Phase 1: O_DIRECT for aligned region (if any)
	if alignedEnd > 0 {
		flags := unix.O_RDONLY
		if useDirect {
			flags |= unix.O_DIRECT
		}

		fd, err := unix.Open(path, flags, 0)
		if err != nil {
			return out, fmt.Errorf("open for hash (direct): %w", err)
		}

		_ = adviseSequential(fd, 0, alignedEnd)

		offset := int64(0)
		for offset < alignedEnd {
			toRead := int64(len(buf))
			if offset+toRead > alignedEnd {
				toRead = alignedEnd - offset
			}

			n, err := unix.Pread(fd, buf[:toRead], offset)
			if err != nil && !errors.Is(err, unix.EINTR) {
				unix.Close(fd)
				return out, fmt.Errorf("pread at %d: %w", offset, err)
			}
			if n == 0 {
				break
			}

			h.Write(buf[:n])
			offset += int64(n)
		}

		unix.Close(fd)
	}

	// Phase 2: Buffered read for tail (if any)
	if hasTail {
		fd, err := unix.Open(path, unix.O_RDONLY, 0) // no O_DIRECT
		if err != nil {
			return out, fmt.Errorf("open for hash (tail): %w", err)
		}

		tailSize := size - alignedEnd
		tailBuf := buf
		if int64(len(tailBuf)) > tailSize {
			tailBuf = tailBuf[:tailSize]
		}

		offset := alignedEnd
		for offset < size {
			toRead := int64(len(tailBuf))
			if offset+toRead > size {
				toRead = size - offset
			}

			n, err := unix.Pread(fd, tailBuf[:toRead], offset)
			if err != nil && !errors.Is(err, unix.EINTR) {
				unix.Close(fd)
				return out, fmt.Errorf("pread tail at %d: %w", offset, err)
			}
			if n == 0 {
				break
			}

			h.Write(tailBuf[:n])
			offset += int64(n)
		}

		unix.Close(fd)
	}

	copy(out[:], h.Sum(nil))
	return out, nil
}

// ============================================================================
// Journal format (append-only, v2)
// ============================================================================

type journalHeader struct {
	Magic    [8]byte
	Version  uint32
	Flags    uint32 // Reserved for future use
	Created  int64
	Hostname [64]byte
	Reserved [48]byte
	CRC32    uint32
}

type commitRecord struct {
	Unix       int64
	Nanos      int32 // Sub-second precision
	PrevDigest [16]byte
	CurrDigest [16]byte
	TargetPath string

	// Full file identity
	Dev   uint64
	Inode uint64
	Nlink uint64
	Mode  uint32
	UID   uint32
	GID   uint32
	Size  uint64

	// Timestamps from stat
	AtimeSec  int64
	AtimeNsec int64
	MtimeSec  int64
	MtimeNsec int64
	CtimeSec  int64
	CtimeNsec int64

	// Wipe details
	WipeMode  uint8
	WipeFlags uint8 // bit0=direct, bit1=mlock, bit2=drop_cache
	Passes    uint8
	Reserved1 uint8
	ChunkSize uint32

	// Hashes
	BeforeHash [32]byte
	AfterHash  [32]byte

	// Record integrity
	RecordCRC32 uint32
}

func ensureJournal(ctx context.Context, tr *tracer, journalPath string, setAppendOnly bool) (*os.File, error) {
	ctx, sp := tr.Start(ctx, "journal.ensure", map[string]string{"path": journalPath})
	defer sp.End()

	f, err := os.OpenFile(journalPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("open journal: %w", err)
	}

	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	if st.Size() == 0 {
		// Initialize new journal
		var hdr journalHeader
		copy(hdr.Magic[:], []byte(journalMagic))
		hdr.Version = version
		hdr.Created = time.Now().Unix()

		hostname, _ := os.Hostname()
		copy(hdr.Hostname[:], []byte(hostname))

		// CRC everything except the CRC field
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, hdr.Magic)
		binary.Write(buf, binary.LittleEndian, hdr.Version)
		binary.Write(buf, binary.LittleEndian, hdr.Flags)
		binary.Write(buf, binary.LittleEndian, hdr.Created)
		binary.Write(buf, binary.LittleEndian, hdr.Hostname)
		binary.Write(buf, binary.LittleEndian, hdr.Reserved)
		hdr.CRC32 = crc32.ChecksumIEEE(buf.Bytes())

		full := new(bytes.Buffer)
		binary.Write(full, binary.LittleEndian, &hdr)
		if _, err := f.WriteAt(full.Bytes(), 0); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
	}

	// Set append-only flag if requested - STRICT enforcement
	if setAppendOnly {
		fd := int(f.Fd())
		if err := modifyFSFlags(fd, FS_APPEND_FL, 0); err != nil {
			f.Close()
			return nil, fmt.Errorf("set journal append-only: %w (requires root or CAP_LINUX_IMMUTABLE)", err)
		}
	}

	// Seek to end for append
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}

	return f, nil
}

func readLastDigest(journalPath string) ([16]byte, error) {
	var zero [16]byte

	f, err := os.Open(journalPath)
	if err != nil {
		return zero, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return zero, err
	}

	headerSize := int64(binary.Size(journalHeader{}))
	if st.Size() <= headerSize {
		return zero, nil // No records yet
	}

	// Read last 16KB to find last record
	const scanBack = 16384
	start := st.Size() - scanBack
	if start < headerSize {
		start = headerSize
	}

	b := make([]byte, st.Size()-start)
	if _, err := f.ReadAt(b, start); err != nil && !errors.Is(err, io.EOF) {
		return zero, err
	}

	// Find last REC1 magic
	idx := bytes.LastIndex(b, []byte(recMagic))
	if idx < 0 {
		return zero, nil
	}

	// Layout: magic[4], headerLen[4], bodyLen[4], unix[8], nanos[4], prev[16], curr[16]...
	// currDigest offset = 4 + 4 + 4 + 8 + 4 + 16 = 40
	currOffset := idx + 40
	if currOffset+16 > len(b) {
		return zero, nil
	}

	var out [16]byte
	copy(out[:], b[currOffset:currOffset+16])
	return out, nil
}

func appendRecord(ctx context.Context, tr *tracer, jf *os.File, r *commitRecord) error {
	ctx, sp := tr.Start(ctx, "journal.append", map[string]string{"target": r.TargetPath})
	defer sp.End()

	pathBytes := []byte(r.TargetPath)
	if len(pathBytes) > 4096 {
		return fmt.Errorf("target path too long: %d bytes", len(pathBytes))
	}

	buf := new(bytes.Buffer)
	buf.WriteString(recMagic)

	// Placeholders for lengths
	headerLenPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint32(0))
	bodyLenPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Fixed header fields
	binary.Write(buf, binary.LittleEndian, r.Unix)
	binary.Write(buf, binary.LittleEndian, r.Nanos)
	buf.Write(r.PrevDigest[:])
	buf.Write(r.CurrDigest[:])

	// Variable-length path
	binary.Write(buf, binary.LittleEndian, uint16(len(pathBytes)))
	buf.Write(pathBytes)

	// File identity
	binary.Write(buf, binary.LittleEndian, r.Dev)
	binary.Write(buf, binary.LittleEndian, r.Inode)
	binary.Write(buf, binary.LittleEndian, r.Nlink)
	binary.Write(buf, binary.LittleEndian, r.Mode)
	binary.Write(buf, binary.LittleEndian, r.UID)
	binary.Write(buf, binary.LittleEndian, r.GID)
	binary.Write(buf, binary.LittleEndian, r.Size)

	// Timestamps
	binary.Write(buf, binary.LittleEndian, r.AtimeSec)
	binary.Write(buf, binary.LittleEndian, r.AtimeNsec)
	binary.Write(buf, binary.LittleEndian, r.MtimeSec)
	binary.Write(buf, binary.LittleEndian, r.MtimeNsec)
	binary.Write(buf, binary.LittleEndian, r.CtimeSec)
	binary.Write(buf, binary.LittleEndian, r.CtimeNsec)

	// Wipe config
	binary.Write(buf, binary.LittleEndian, r.WipeMode)
	binary.Write(buf, binary.LittleEndian, r.WipeFlags)
	binary.Write(buf, binary.LittleEndian, r.Passes)
	binary.Write(buf, binary.LittleEndian, r.Reserved1)
	binary.Write(buf, binary.LittleEndian, r.ChunkSize)

	// Hashes
	buf.Write(r.BeforeHash[:])
	buf.Write(r.AfterHash[:])

	// Fix up lengths
	raw := buf.Bytes()
	headerLen := uint32(4 + 4 + 4) // magic + 2 lengths
	bodyLen := uint32(len(raw) - int(headerLen))
	binary.LittleEndian.PutUint32(raw[headerLenPos:], headerLen)
	binary.LittleEndian.PutUint32(raw[bodyLenPos:], bodyLen)

	// CRC of everything - populate struct field for envelope/verification
	r.RecordCRC32 = crc32.ChecksumIEEE(raw)

	// Write record + CRC
	if _, err := jf.Write(raw); err != nil {
		return err
	}
	if err := binary.Write(jf, binary.LittleEndian, r.RecordCRC32); err != nil {
		return err
	}

	// fsync the journal
	return jf.Sync()
}

// ============================================================================
// Digest chain computation
// ============================================================================

func computeDigest16(prev [16]byte, before [32]byte, after [32]byte, id FileIdentity, unix int64, nanos int32) [16]byte {
	h := sha256.New()
	h.Write(prev[:])
	h.Write(before[:])
	h.Write(after[:])

	var buf [64]byte
	binary.LittleEndian.PutUint64(buf[0:8], id.Dev)
	binary.LittleEndian.PutUint64(buf[8:16], id.Inode)
	binary.LittleEndian.PutUint64(buf[16:24], uint64(id.Size))
	binary.LittleEndian.PutUint32(buf[24:28], id.Mode)
	binary.LittleEndian.PutUint32(buf[28:32], id.UID)
	binary.LittleEndian.PutUint32(buf[32:36], id.GID)
	binary.LittleEndian.PutUint64(buf[36:44], uint64(unix))
	binary.LittleEndian.PutUint32(buf[44:48], uint32(nanos))
	h.Write(buf[:48])

	sum := h.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// ============================================================================
// Tracer (Zipkin-compatible)
// ============================================================================

type zipkinEndpoint struct {
	ServiceName string `json:"serviceName"`
}

type zipkinSpan struct {
	TraceID       string            `json:"traceId"`
	ID            string            `json:"id"`
	ParentID      string            `json:"parentId,omitempty"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind,omitempty"`
	TsMicros      int64             `json:"timestamp"`
	DurMicros     int64             `json:"duration"`
	LocalEndpoint zipkinEndpoint    `json:"localEndpoint"`
	Tags          map[string]string `json:"tags,omitempty"`
}

type spanKey struct{}

type tracer struct {
	mu      sync.Mutex
	service string
	traceID string
	spans   []zipkinSpan
}

func newTracer(service string) *tracer {
	var b [16]byte
	_ = cryptoRandFill(b[:])
	return &tracer{
		service: service,
		traceID: hex.EncodeToString(b[:]),
	}
}

func newSpanID() string {
	var b [8]byte
	_ = cryptoRandFill(b[:])
	return hex.EncodeToString(b[:])
}

type spanHandle struct {
	tr     *tracer
	id     string
	parent string
	name   string
	start  time.Time
	tags   map[string]string
}

func (t *tracer) Start(ctx context.Context, name string, tags map[string]string) (context.Context, *spanHandle) {
	parent := ""
	if v := ctx.Value(spanKey{}); v != nil {
		if s, ok := v.(string); ok {
			parent = s
		}
	}
	h := &spanHandle{
		tr:     t,
		id:     newSpanID(),
		parent: parent,
		name:   name,
		start:  time.Now(),
		tags:   tags,
	}
	return context.WithValue(ctx, spanKey{}, h.id), h
}

func (h *spanHandle) End() {
	s := zipkinSpan{
		TraceID:       h.tr.traceID,
		ID:            h.id,
		ParentID:      h.parent,
		Name:          h.name,
		TsMicros:      h.start.UnixMicro(),
		DurMicros:     time.Since(h.start).Microseconds(),
		LocalEndpoint: zipkinEndpoint{ServiceName: h.tr.service},
		Tags:          h.tags,
	}
	h.tr.mu.Lock()
	h.tr.spans = append(h.tr.spans, s)
	h.tr.mu.Unlock()
}

func (t *tracer) Flush(ctx context.Context, zipkinURL, fallbackPath string) error {
	t.mu.Lock()
	payload := append([]zipkinSpan(nil), t.spans...)
	t.mu.Unlock()

	if len(payload) == 0 {
		return nil
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	if zipkinURL != "" {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, zipkinURL, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				log.Printf("trace: flushed %d spans to %s", len(payload), zipkinURL)
				return nil
			}
			err = fmt.Errorf("zipkin status=%s", resp.Status)
		}
		log.Printf("trace: zipkin failed: %v (writing fallback)", err)
	}

	if fallbackPath == "" {
		fallbackPath = "filcommit_trace_spans.json"
	}
	if err := os.WriteFile(fallbackPath, b, 0644); err != nil {
		return err
	}
	log.Printf("trace: wrote %d spans to %s", len(payload), fallbackPath)
	return nil
}

// ============================================================================
// Main
// ============================================================================

func main() {
	var (
		path                  = flag.String("path", "", "Target file to commit-delete")
		journal               = flag.String("journal", "", "Journal file (default: <dir>/.filcommit.journal)")
		wipeMode              = flag.String("wipe", "zero", "Wipe mode: zero|random|punch|pattern")
		chunk                 = flag.Int("chunk", 1<<20, "Chunk size in bytes")
		passes                = flag.Int("passes", 1, "Number of wipe passes (pattern mode uses 3)")
		useDirect             = flag.Bool("direct", false, "Use O_DIRECT (bypass page cache)")
		useMlock              = flag.Bool("mlock", true, "mlock buffers (prevent swap)")
		dropCache             = flag.Bool("drop_cache", true, "FADV_DONTNEED after wipe")
		syncEvery             = flag.Int("sync_every", 0, "fdatasync every N chunks (0=end only)")
		setAppendOnlyJournal  = flag.Bool("set_append_only_journal", true, "Set journal append-only")
		lockTarget            = flag.Bool("lock_target", false, "Set target immutable after wipe")
		unlockTargetFirst     = flag.Bool("unlock_target_first", true, "Clear flags before wipe")
		zipkinURL             = flag.String("zipkin_url", "", "Zipkin collector URL")
		traceFallback         = flag.String("trace_fallback", "filcommit_trace.json", "Trace fallback file")
		printEnvelope         = flag.Bool("print_envelope", true, "Print Base64 JSON envelope")
		syncFS                = flag.Bool("syncfs", false, "syncfs entire filesystem after commit")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if runtime.GOOS != "linux" {
		log.Fatalf("filcommit requires Linux (detected: %s)", runtime.GOOS)
	}
	if *path == "" {
		log.Fatal("missing -path")
	}

	mode, err := ParseWipeMode(*wipeMode)
	if err != nil {
		log.Fatal(err)
	}
	if mode == WipeModePattern && *passes < 3 {
		*passes = 3 // DoD 5220.22-M minimum
	}

	// STRICT privilege checks upfront - fail fast if we can't deliver requested guarantees
	if *setAppendOnlyJournal {
		if err := requirePriv("set journal append-only"); err != nil {
			log.Fatalf("%v", err)
		}
	}
	if *unlockTargetFirst || *lockTarget {
		if err := requirePriv("set/clear target file flags"); err != nil {
			log.Fatalf("%v", err)
		}
	}

	tr := newTracer("filcommit")
	ctx := context.Background()
	ctx, root := tr.Start(ctx, "filcommit.run", map[string]string{"path": *path, "mode": *wipeMode})
	defer root.End()
	defer func() { _ = tr.Flush(context.Background(), *zipkinURL, *traceFallback) }()

	absPath, err := filepath.Abs(*path)
	if err != nil {
		log.Fatalf("abs path: %v", err)
	}

	// Open target and get identity
	ctx, spOpen := tr.Start(ctx, "target.open", nil)
	fd, err := unix.Open(absPath, unix.O_RDWR, 0)
	spOpen.End()
	if err != nil {
		log.Fatalf("open target: %v", err)
	}
	defer unix.Close(fd)

	id, err := getFileIdentity(fd)
	if err != nil {
		log.Fatalf("stat: %v", err)
	}
	if id.Mode&unix.S_IFMT == unix.S_IFDIR {
		log.Fatalf("target is a directory: %s", absPath)
	}
	if id.Size < 0 {
		log.Fatalf("invalid file size: %d", id.Size)
	}

	// Journal setup
	jpath := *journal
	if jpath == "" {
		jpath = filepath.Join(filepath.Dir(absPath), ".filcommit.journal")
	}

	jf, err := ensureJournal(ctx, tr, jpath, *setAppendOnlyJournal)
	if err != nil {
		log.Fatalf("journal: %v", err)
	}
	defer jf.Close()

	// Before hash
	before, err := sha256File(ctx, tr, absPath, *useDirect, *useMlock)
	if err != nil {
		log.Fatalf("sha256(before): %v", err)
	}

	// Unlock target if needed - STRICT enforcement
	if *unlockTargetFirst {
		ctx, sp := tr.Start(ctx, "target.unlock", nil)
		if err := modifyFSFlags(fd, 0, FS_APPEND_FL|FS_IMMUTABLE_FL); err != nil {
			sp.End()
			log.Fatalf("unlock target flags: %v", err)
		}
		sp.End()
	}

	// Wipe
	cfg := WipeConfig{
		Mode:      mode,
		ChunkSize: *chunk,
		Passes:    *passes,
		UseDirect: *useDirect,
		UseMlock:  *useMlock,
		SyncEvery: *syncEvery,
		DropCache: *dropCache,
	}
	if err := wipeFile(ctx, tr, absPath, id.Size, cfg); err != nil {
		log.Fatalf("wipe: %v", err)
	}

	// After hash
	after, err := sha256File(ctx, tr, absPath, *useDirect, *useMlock)
	if err != nil {
		log.Fatalf("sha256(after): %v", err)
	}

	// Build chain digest
	prevDigest, err := readLastDigest(jpath)
	if err != nil {
		log.Printf("warn: readLastDigest: %v", err)
	}

	now := time.Now()
	currDigest := computeDigest16(prevDigest, before, after, id, now.Unix(), int32(now.Nanosecond()))

	// Wipe flags byte
	var wipeFlags uint8
	if *useDirect {
		wipeFlags |= 0x01
	}
	if *useMlock {
		wipeFlags |= 0x02
	}
	if *dropCache {
		wipeFlags |= 0x04
	}

	// Append record
	rec := commitRecord{
		Unix:       now.Unix(),
		Nanos:      int32(now.Nanosecond()),
		PrevDigest: prevDigest,
		CurrDigest: currDigest,
		TargetPath: absPath,
		Dev:        id.Dev,
		Inode:      id.Inode,
		Nlink:      id.Nlink,
		Mode:       id.Mode,
		UID:        id.UID,
		GID:        id.GID,
		Size:       uint64(id.Size),
		AtimeSec:   id.Atime.Sec,
		AtimeNsec:  id.Atime.Nsec,
		MtimeSec:   id.Mtime.Sec,
		MtimeNsec:  id.Mtime.Nsec,
		CtimeSec:   id.Ctime.Sec,
		CtimeNsec:  id.Ctime.Nsec,
		WipeMode:   uint8(mode),
		WipeFlags:  wipeFlags,
		Passes:     uint8(*passes),
		ChunkSize:  uint32(*chunk),
		BeforeHash: before,
		AfterHash:  after,
	}
	if err := appendRecord(ctx, tr, jf, &rec); err != nil {
		log.Fatalf("append record: %v", err)
	}

	// Lock target if requested - STRICT enforcement
	if *lockTarget {
		ctx, sp := tr.Start(ctx, "target.lock", nil)
		if err := modifyFSFlags(fd, FS_IMMUTABLE_FL, FS_APPEND_FL); err != nil {
			sp.End()
			log.Fatalf("lock target immutable: %v", err)
		}
		sp.End()
	}

	// Filesystem sync if requested
	if *syncFS {
		ctx, sp := tr.Start(ctx, "syncfs", nil)
		if err := syncFilesystem(fd); err != nil {
			log.Printf("warn: syncfs: %v", err)
		}
		sp.End()
	}

	// Envelope output
	if *printEnvelope {
		env := map[string]any{
			"tool":        "filcommit",
			"v":           version,
			"t":           now.Unix(),
			"t_ns":        now.Nanosecond(),
			"path":        absPath,
			"dev":         id.Dev,
			"inode":       id.Inode,
			"size":        id.Size,
			"uid":         id.UID,
			"gid":         id.GID,
			"mode":        fmt.Sprintf("%04o", id.Mode&0777),
			"wipe":        mode.String(),
			"passes":      *passes,
			"direct":      *useDirect,
			"before_b64":  base64.StdEncoding.EncodeToString(before[:]),
			"after_b64":   base64.StdEncoding.EncodeToString(after[:]),
			"prev16_hex":  hex.EncodeToString(prevDigest[:]),
			"curr16_hex":  hex.EncodeToString(currDigest[:]),
			"rec_crc32":   fmt.Sprintf("%08x", rec.RecordCRC32),
			"journal":     jpath,
		}
		b, _ := json.Marshal(env)
		fmt.Println(base64.StdEncoding.EncodeToString(b))
	}

	log.Printf("ok path=%s size=%d inode=%d digest=%s crc=%08x",
		absPath, id.Size, id.Inode, hex.EncodeToString(currDigest[:]), rec.RecordCRC32)
}
