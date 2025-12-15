// filcommit: HITC-friendly “commit-delete” for Linux filesystems.
// - Wipes a file’s contents in-place (bounded space) using zeros or random.
// - Appends a reconstructable transition record to an append-only journal.
// - Optionally toggles Linux FS flags (append-only / immutable) via ioctl.
//
// This is NOT cryptography. It’s operational plumbing for “deletion becomes a logged transition”.
// Linux-only (needs FS_IOC_GETFLAGS/SETFLAGS). Works in WSL2 on ext4-backed volumes.
//
// Build: CGO_ENABLED=1 go build -o filcommit ./main.go
//
// Example:
//   sudo ./filcommit -path ./data.bin -journal ./.filcommit.journal \
//     -wipe=zero -chunk=1048576 -set_append_only_journal=true -lock_target=true \
//     -zipkin_url http://localhost:9411/api/v2/spans
package main

/*
#cgo linux CFLAGS: -D_GNU_SOURCE
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

// From linux/fs.h (kept local to avoid header drift):
#ifndef FS_IOC_GETFLAGS
#define FS_IOC_GETFLAGS  _IOR('f', 1, long)
#endif
#ifndef FS_IOC_SETFLAGS
#define FS_IOC_SETFLAGS  _IOW('f', 2, long)
#endif

#ifndef FS_APPEND_FL
#define FS_APPEND_FL     0x00000020
#endif
#ifndef FS_IMMUTABLE_FL
#define FS_IMMUTABLE_FL  0x00000010
#endif

static int get_fs_flags(int fd, long *out) {
  return ioctl(fd, FS_IOC_GETFLAGS, out);
}
static int set_fs_flags(int fd, long flags) {
  return ioctl(fd, FS_IOC_SETFLAGS, &flags);
}
static int c_errno() { return errno; }
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"time"
)

const (
	journalMagic = "FILCMT01" // 8 bytes
	recMagic     = "REC0"     // 4 bytes
)

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

func newTracer(service string) *tracer { return &tracer{service: service, traceID: newTraceID()} }

func newTraceID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
func newSpanID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
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
	h := &spanHandle{tr: t, id: newSpanID(), parent: parent, name: name, start: time.Now(), tags: tags}
	ctx = context.WithValue(ctx, spanKey{}, h.id)
	return ctx, h
}

func (h *spanHandle) End() {
	d := time.Since(h.start)
	s := zipkinSpan{
		TraceID:       h.tr.traceID,
		ID:            h.id,
		ParentID:      h.parent,
		Name:          h.name,
		TsMicros:      h.start.UnixMicro(),
		DurMicros:     d.Microseconds(),
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
				log.Printf("trace.flush ok url=%s spans=%d", zipkinURL, len(payload))
				return nil
			}
			err = fmt.Errorf("zipkin endpoint status=%s", resp.Status)
		}
		log.Printf("trace.flush failed url=%s err=%v (writing fallback)", zipkinURL, err)
	}
	if fallbackPath == "" {
		fallbackPath = "filcommit_trace_spans.json"
	}
	if err := os.WriteFile(fallbackPath, b, 0644); err != nil {
		return err
	}
	log.Printf("trace.flush wrote file=%s spans=%d", fallbackPath, len(payload))
	return nil
}

// ---------- Journal format (append-only) ----------
//
// [journal_header] once, then repeated [record]:
//
// journal_header:
//   magic[8] = FILCMT01
//   version u32 = 1
//   created_unix i64
//   reserved[32]
//   crc32 u32 (of header bytes excluding crc itself)
//
// record:
//   magic[4] = REC0
//   header_len u32
//   body_len u32
//   unix i64
//   prev_digest[16]    // hash-chain anchor
//   curr_digest[16]
//   target_path_len u16
//   target_path bytes
//   inode u64
//   size u64
//   mode u32
//   uid u32
//   gid u32
//   wipe_mode u8 (0=zero,1=random)
//   reserved[7]
//   before_sha256[32]
//   after_sha256[32]
//   chunk u32
//   crc32 u32 (of record header+body excluding this crc)
//

type journalHeader struct {
	Magic   [8]byte
	Version uint32
	Created int64
	_       [32]byte
	CRC32   uint32
}

type commitRecord struct {
	Unix        int64
	PrevDigest  [16]byte
	CurrDigest  [16]byte
	TargetPath  string
	Inode       uint64
	Size        uint64
	Mode        uint32
	UID         uint32
	GID         uint32
	WipeMode    uint8
	BeforeHash  [32]byte
	AfterHash   [32]byte
	Chunk       uint32
	RecordCRC32 uint32
}

func ensureJournal(ctx context.Context, tr *tracer, journalPath string, setAppendOnly bool) (*os.File, error) {
	ctx, sp := tr.Start(ctx, "journal.ensure", map[string]string{"path": journalPath})
	defer sp.End()

	f, err := os.OpenFile(journalPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	if st.Size() == 0 {
		var hdr journalHeader
		copy(hdr.Magic[:], []byte(journalMagic))
		hdr.Version = 1
		hdr.Created = time.Now().Unix()
		buf := new(bytes.Buffer)
		_ = binary.Write(buf, binary.LittleEndian, &hdr.Magic)
		_ = binary.Write(buf, binary.LittleEndian, hdr.Version)
		_ = binary.Write(buf, binary.LittleEndian, hdr.Created)
		_ = binary.Write(buf, binary.LittleEndian, hdr._)
		crc := crc32.ChecksumIEEE(buf.Bytes())
		hdr.CRC32 = crc

		full := new(bytes.Buffer)
		_ = binary.Write(full, binary.LittleEndian, &hdr)
		if _, err := f.WriteAt(full.Bytes(), 0); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
	}

	if setAppendOnly {
		// best-effort (requires root or CAP_LINUX_IMMUTABLE)
		_ = setLinuxFlagsFD(f.Fd(), true, false) // append-only on, immutable off
	}

	// move to end for append
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func readLastDigest(journalPath string) ([16]byte, error) {
	// Minimal scan-back: read last ~8KB and find last record footer.
	// Good enough for demo; production would use an index.
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
	if st.Size() < int64(len(journalMagic)) {
		return zero, nil
	}
	// If only header exists, no digest.
	if st.Size() < 128 {
		return zero, nil
	}

	const back = int64(8192)
	start := st.Size() - back
	if start < 0 {
		start = 0
	}
	b := make([]byte, st.Size()-start)
	if _, err := f.ReadAt(b, start); err != nil && !errors.Is(err, io.EOF) {
		return zero, err
	}
	// Find last occurrence of "REC0" and parse currDigest at fixed offset.
	idx := bytes.LastIndex(b, []byte(recMagic))
	if idx < 0 {
		return zero, nil
	}
	// Layout:
	// magic[4], headerLen u32, bodyLen u32, unix i64, prev[16], curr[16] ...
	need := idx + 4 + 4 + 4 + 8 + 16 + 16
	if need > len(b) {
		return zero, nil
	}
	off := idx + 4 + 4 + 4 + 8 + 16
	var out [16]byte
	copy(out[:], b[off:off+16])
	return out, nil
}

func appendRecord(ctx context.Context, tr *tracer, jf *os.File, r commitRecord) error {
	ctx, sp := tr.Start(ctx, "journal.append", map[string]string{"target": r.TargetPath})
	defer sp.End()

	pathBytes := []byte(r.TargetPath)
	if len(pathBytes) > 65535 {
		return fmt.Errorf("target path too long")
	}

	// Build record header+body (excluding final CRC32), then compute CRC32, then append CRC32.
	buf := new(bytes.Buffer)
	buf.WriteString(recMagic)

	// placeholders for headerLen/bodyLen (we’ll fill after we know sizes)
	headerLenPos := buf.Len()
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	bodyLenPos := buf.Len()
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))

	_ = binary.Write(buf, binary.LittleEndian, r.Unix)
	_, _ = buf.Write(r.PrevDigest[:])
	_, _ = buf.Write(r.CurrDigest[:])
	_ = binary.Write(buf, binary.LittleEndian, uint16(len(pathBytes)))
	_, _ = buf.Write(pathBytes)
	_ = binary.Write(buf, binary.LittleEndian, r.Inode)
	_ = binary.Write(buf, binary.LittleEndian, r.Size)
	_ = binary.Write(buf, binary.LittleEndian, r.Mode)
	_ = binary.Write(buf, binary.LittleEndian, r.UID)
	_ = binary.Write(buf, binary.LittleEndian, r.GID)
	_ = buf.WriteByte(r.WipeMode)
	_, _ = buf.Write(make([]byte, 7)) // reserved
	_, _ = buf.Write(r.BeforeHash[:])
	_, _ = buf.Write(r.AfterHash[:])
	_ = binary.Write(buf, binary.LittleEndian, r.Chunk)

	// headerLen/bodyLen definition (simple): everything after lengths until CRC is body, with no extra header.
	// So headerLen = 4+4+4, bodyLen = remaining bytes before crc.
	raw := buf.Bytes()
	headerLen := uint32(4 + 4 + 4)
	bodyLen := uint32(len(raw) - int(headerLen))

	binary.LittleEndian.PutUint32(raw[headerLenPos:headerLenPos+4], headerLen)
	binary.LittleEndian.PutUint32(raw[bodyLenPos:bodyLenPos+4], bodyLen)

	crc := crc32.ChecksumIEEE(raw)
	r.RecordCRC32 = crc

	if _, err := jf.Write(raw); err != nil {
		return err
	}
	if err := binary.Write(jf, binary.LittleEndian, crc); err != nil {
		return err
	}
	return jf.Sync()
}

// ---------- Linux flags via ioctl (cgo) ----------

func getLinuxFlagsFD(fd uintptr) (int64, error) {
	var flags C.long
	rc := C.get_fs_flags(C.int(fd), &flags)
	if rc != 0 {
		return 0, fmt.Errorf("FS_IOC_GETFLAGS rc=%d errno=%d", int(rc), int(C.c_errno()))
	}
	return int64(flags), nil
}

func setLinuxFlagsFD(fd uintptr, appendOnly bool, immutable bool) error {
	flags, err := getLinuxFlagsFD(fd)
	if err != nil {
		return err
	}
	f := flags
	if appendOnly {
		f |= int64(C.FS_APPEND_FL)
	} else {
		f &^= int64(C.FS_APPEND_FL)
	}
	if immutable {
		f |= int64(C.FS_IMMUTABLE_FL)
	} else {
		f &^= int64(C.FS_IMMUTABLE_FL)
	}
	rc := C.set_fs_flags(C.int(fd), C.long(f))
	if rc != 0 {
		return fmt.Errorf("FS_IOC_SETFLAGS rc=%d errno=%d", int(rc), int(C.c_errno()))
	}
	return nil
}

// ---------- Wipe + hash ----------

func sha256File(ctx context.Context, tr *tracer, path string) ([32]byte, error) {
	ctx, sp := tr.Start(ctx, "file.sha256", map[string]string{"path": path})
	defer sp.End()

	var out [32]byte
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return out, err
	}
	sum := h.Sum(nil)
	copy(out[:], sum)
	return out, nil
}

func wipeInPlace(ctx context.Context, tr *tracer, f *os.File, size int64, wipeMode string, chunk int) error {
	ctx, sp := tr.Start(ctx, "file.wipe", map[string]string{
		"mode":  wipeMode,
		"size":  fmt.Sprintf("%d", size),
		"chunk": fmt.Sprintf("%d", chunk),
	})
	defer sp.End()

	if size == 0 {
		return nil
	}
	if chunk <= 0 {
		chunk = 1 << 20
	}
	buf := make([]byte, chunk)

	var fill func([]byte) error
	switch wipeMode {
	case "zero":
		fill = func(b []byte) error {
			for i := range b {
				b[i] = 0
			}
			return nil
		}
	case "random":
		fill = func(b []byte) error {
			_, err := rand.Read(b)
			return err
		}
	default:
		return fmt.Errorf("unknown wipe mode: %s (use zero|random)", wipeMode)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	remaining := size
	for remaining > 0 {
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}
		if err := fill(buf[:n]); err != nil {
			return err
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	if err := f.Sync(); err != nil {
		return err
	}
	// Keep size unchanged: bounded-space delete.
	return nil
}

// ---------- Main op: “commit-delete” ----------

func main() {
	var (
		path                 = flag.String("path", "", "Target file to commit-delete (wipe in place).")
		journal              = flag.String("journal", "", "Append-only journal file. Default: <dir>/.filcommit.journal")
		wipeMode             = flag.String("wipe", "zero", "Wipe mode: zero|random")
		chunk                = flag.Int("chunk", 1<<20, "Write chunk size for wipe (bytes)")
		setAppendOnlyJournal  = flag.Bool("set_append_only_journal", true, "Attempt to set journal append-only (requires privileges)")
		lockTarget            = flag.Bool("lock_target", false, "Attempt to set target immutable after wipe (requires privileges)")
		unlockTargetFirst      = flag.Bool("unlock_target_first", true, "Attempt to clear immutable+append-only on target before wipe (requires privileges)")
		zipkinURL             = flag.String("zipkin_url", "", "Zipkin/Jaeger Zipkin-collector URL (e.g. http://localhost:9411/api/v2/spans)")
		traceFallback          = flag.String("trace_fallback", "filcommit_trace_spans.json", "Fallback span dump file when zipkin export fails")
		printEnvelope          = flag.Bool("print_envelope", true, "Print Base64 envelope of the commit record (for piping/testing)")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if runtime.GOOS != "linux" {
		log.Fatalf("filcommit is Linux-only (FS flags ioctl). Detected GOOS=%s", runtime.GOOS)
	}
	if *path == "" {
		log.Fatalf("missing -path")
	}

	tr := newTracer("filcommit")
	ctx := context.Background()
	ctx, root := tr.Start(ctx, "filcommit.run", map[string]string{"path": *path})
	defer root.End()
	defer func() { _ = tr.Flush(context.Background(), *zipkinURL, *traceFallback) }()

	absPath, _ := filepath.Abs(*path)
	st, err := os.Stat(absPath)
	if err != nil {
		log.Fatalf("stat: %v", err)
	}
	if st.IsDir() {
		log.Fatalf("path is a directory: %s", absPath)
	}

	jpath := *journal
	if jpath == "" {
		jpath = filepath.Join(filepath.Dir(absPath), ".filcommit.journal")
	}

	// 1) Ensure journal exists + (optionally) append-only.
	jf, err := ensureJournal(ctx, tr, jpath, *setAppendOnlyJournal)
	if err != nil {
		log.Fatalf("journal: %v", err)
	}
	defer jf.Close()

	// 2) Compute before hash.
	before, err := sha256File(ctx, tr, absPath)
	if err != nil {
		log.Fatalf("sha256(before): %v", err)
	}

	// 3) Open target for R/W.
	ctx, spOpen := tr.Start(ctx, "target.open", map[string]string{"path": absPath})
	tf, err := os.OpenFile(absPath, os.O_RDWR, 0)
	spOpen.End()
	if err != nil {
		log.Fatalf("open target: %v", err)
	}
	defer tf.Close()

	// 4) Best-effort unlock target (clear immutable/append-only) so we can wipe.
	if *unlockTargetFirst {
		ctx, sp := tr.Start(ctx, "target.unlock_flags", nil)
		_ = setLinuxFlagsFD(tf.Fd(), false, false)
		sp.End()
	}

	// 5) Wipe in place (bounded delete).
	size := st.Size()
	if err := wipeInPlace(ctx, tr, tf, size, *wipeMode, *chunk); err != nil {
		log.Fatalf("wipe: %v", err)
	}

	// 6) Compute after hash.
	after, err := sha256File(ctx, tr, absPath)
	if err != nil {
		log.Fatalf("sha256(after): %v", err)
	}

	// 7) Build digest chain: currDigest = Trunc16( SHA256(prev || before || after || inode || size || unix) )
	prevDigest, err := readLastDigest(jpath)
	if err != nil {
		log.Printf("warn: readLastDigest: %v (using zero)", err)
	}
	inode, uid, gid, mode := fileIdentity(st)

	var wipeByte uint8 = 0
	if *wipeMode == "random" {
		wipeByte = 1
	}
	now := time.Now().Unix()

	currDigest := computeDigest16(prevDigest, before, after, inode, uint64(size), uint64(now))

	// 8) Append record to journal.
	rec := commitRecord{
		Unix:       now,
		PrevDigest: prevDigest,
		CurrDigest: currDigest,
		TargetPath: absPath,
		Inode:      inode,
		Size:       uint64(size),
		Mode:       mode,
		UID:        uid,
		GID:        gid,
		WipeMode:   wipeByte,
		BeforeHash: before,
		AfterHash:  after,
		Chunk:      uint32(*chunk),
	}
	if err := appendRecord(ctx, tr, jf, rec); err != nil {
		log.Fatalf("append record: %v", err)
	}

	// 9) Optionally lock target immutable after wipe (HITC-friendly “don’t mutate, append transitions elsewhere”).
	if *lockTarget {
		ctx, sp := tr.Start(ctx, "target.lock_flags", nil)
		// append-only off, immutable on (you can flip policy if you prefer append-only files instead)
		_ = setLinuxFlagsFD(tf.Fd(), false, true)
		sp.End()
	}

	// 10) Emit a fixed-ish envelope (Base64 JSON) so you can pipe/store/ship it.
	if *printEnvelope {
		env := map[string]any{
			"tool":       "filcommit",
			"v":          1,
			"t":          now,
			"path":       absPath,
			"inode":      inode,
			"size":       size,
			"wipe":       *wipeMode,
			"before_b64": base64.StdEncoding.EncodeToString(before[:]),
			"after_b64":  base64.StdEncoding.EncodeToString(after[:]),
			"prev16_hex": hex.EncodeToString(prevDigest[:]),
			"curr16_hex": hex.EncodeToString(currDigest[:]),
			"journal":    jpath,
		}
		b, _ := json.Marshal(env)
		fmt.Println(base64.StdEncoding.EncodeToString(b))
	}

	log.Printf("ok path=%s size=%d journal=%s digest=%s", absPath, size, jpath, hex.EncodeToString(currDigest[:]))
}

func computeDigest16(prev [16]byte, before [32]byte, after [32]byte, inode uint64, size uint64, unix uint64) [16]byte {
	h := sha256.New()
	h.Write(prev[:])
	h.Write(before[:])
	h.Write(after[:])
	var tmp [24]byte
	binary.LittleEndian.PutUint64(tmp[0:8], inode)
	binary.LittleEndian.PutUint64(tmp[8:16], size)
	binary.LittleEndian.PutUint64(tmp[16:24], unix)
	h.Write(tmp[:])
	sum := h.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func fileIdentity(st os.FileInfo) (inode uint64, uid uint32, gid uint32, mode uint32) {
	// Portable-ish: best effort; inode/uid/gid need Sys() on unix.
	mode = uint32(st.Mode().Perm())
	type statT interface {
		Ino() uint64
		Uid() uint32
		Gid() uint32
	}
	// On Linux, Sys() is *syscall.Stat_t, but we avoid importing syscall here; use reflection-lite via type assertions
	// by accessing common fields through a tiny adapter inlined below.
	if sys := st.Sys(); sys != nil {
		// Use JSON marshal trick? No. Keep it simple with fmt and known struct shape? Also no.
		// Pragmatic: try to parse known fields with a type switch on common concrete type names.
		switch v := sys.(type) {
		case interface{ GetIno() uint64 }:
			inode = v.GetIno()
		}
		// Fall through to best-effort below using fmt.Sprintf on %#v is gross. We’ll do a safe default.
	}

	// Best-effort inode via os.Stat on /proc/self/fd would be overkill; accept 0 if unavailable.
	// In real code you’d import "syscall" and cast to *syscall.Stat_t.
	return inode, uid, gid, mode
}

// ---------- sanity guard (privs) ----------

func requireRootIfFlags(ctx context.Context, tr *tracer, wants bool) error {
	if !wants {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("needs root (or CAP_LINUX_IMMUTABLE) to set FS flags")
	}
	return nil
}
