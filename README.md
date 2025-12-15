# filcommit v2 — Hardened HITC Commit-Delete

Kernel-level hardened "deletion becomes a logged transition" utility for Linux filesystems.

## What Changed (v1 → v2)

### CGO Eliminated
- **Before**: Required `CGO_ENABLED=1` for ioctl calls
- **After**: Pure Go via `golang.org/x/sys/unix` direct syscalls
- **Why**: Simpler cross-compilation, no C toolchain needed, cleaner error handling

### Proper Syscall-Level Identity
- **Before**: `fileIdentity()` returned zeros for inode/uid/gid (stub code)
- **After**: Full `unix.Stat_t` extraction — dev, inode, nlink, mode, uid, gid, all three timestamps (atime/mtime/ctime with nanosecond precision)
- **Why**: Forensic-grade provenance chain requires complete file identity

### Memory Security

```go
// secureZero with memory barrier — defeats dead-store elimination
func secureZero(b []byte) {
    for i := range b { b[i] = 0 }
    atomic.StoreUint32(&dummy, 0)  // fence
    runtime.KeepAlive(b)
}

// mlock to prevent sensitive buffers hitting swap
unix.Mlock(buf)
```

### O_DIRECT Support
- Bypasses page cache entirely — data goes straight to disk
- Critical for secure wipe: ensures previous content isn't lingering in kernel buffers
- Requires page-aligned buffers (4096-byte alignment)

```bash
./filcommit -path ./secrets.bin -direct=true -wipe=random
```

### Entropy Source
- **Before**: `crypto/rand.Read()` (userspace CSPRNG)
- **After**: `unix.Getrandom()` — direct syscall to kernel entropy pool
- **Why**: Eliminates userspace buffering, guaranteed kernel-quality randomness

### Sync Semantics
| Function | What it syncs |
|----------|--------------|
| `fdatasync` | Data blocks only |
| `fsync` | Data + metadata (inode) |
| `syncfs` | Entire filesystem |

New `-syncfs=true` flag for paranoid mode — ensures journal and target hit stable storage before returning.

### posix_fadvise Hints
```go
unix.Fadvise(fd, 0, size, unix.FADV_SEQUENTIAL)  // hint: we'll read linearly
unix.Fadvise(fd, 0, size, unix.FADV_DONTNEED)    // after wipe: drop from cache
```

### Wipe Modes

| Mode | Description |
|------|-------------|
| `zero` | Overwrite with 0x00 (fast, SSD-friendly) |
| `random` | getrandom(2) entropy per chunk |
| `punch` | `fallocate(PUNCH_HOLE)` — sparse-aware, deallocates blocks |
| `pattern` | DoD 5220.22-M: 0x00 → 0xFF → random (3-pass minimum) |

```bash
# Sparse-aware deletion (filesystem reclaims blocks)
./filcommit -path ./bigfile.bin -wipe=punch

# DoD-style multi-pass
./filcommit -path ./classified.bin -wipe=pattern -passes=7
```

### Journal Format v2
Extended record with full forensic metadata:
- Nanosecond timestamp precision
- Device ID (`st_dev`)
- Hard link count (`st_nlink`)
- All three timestamps with nsec
- Wipe configuration flags

### ioctl via Pure Go
```go
// No more CGO — direct syscall
func getFSFlags(fd int) (int32, error) {
    var flags int32
    _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
        uintptr(FS_IOC_GETFLAGS), uintptr(unsafe.Pointer(&flags)))
    if errno != 0 {
        return 0, fmt.Errorf("FS_IOC_GETFLAGS: %w", errno)
    }
    return flags, nil
}
```

## Build

```bash
go build -o filcommit .
```

No CGO required. Cross-compile trivially:
```bash
GOOS=linux GOARCH=amd64 go build -o filcommit-amd64 .
GOOS=linux GOARCH=arm64 go build -o filcommit-arm64 .
```

## Usage

```bash
# Basic zero-wipe with mlock'd buffers
sudo ./filcommit -path ./data.bin

# Full hardening: O_DIRECT + random + filesystem sync
sudo ./filcommit -path ./sensitive.bin \
    -wipe=random \
    -direct=true \
    -mlock=true \
    -syncfs=true \
    -lock_target=true

# Sparse-file aware (punch hole)
sudo ./filcommit -path ./sparse.img -wipe=punch

# With distributed tracing
sudo ./filcommit -path ./data.bin \
    -zipkin_url=http://jaeger:9411/api/v2/spans
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-path` | required | Target file |
| `-journal` | `<dir>/.filcommit.journal` | Append-only journal |
| `-wipe` | `zero` | `zero\|random\|punch\|pattern` |
| `-chunk` | 1048576 | I/O chunk size (bytes) |
| `-passes` | 1 | Wipe passes (pattern forces ≥3) |
| `-direct` | false | O_DIRECT (bypass page cache) |
| `-mlock` | true | mlock sensitive buffers |
| `-drop_cache` | true | FADV_DONTNEED after wipe |
| `-sync_every` | 0 | fdatasync interval (0=end only) |
| `-syncfs` | false | Sync entire filesystem |
| `-set_append_only_journal` | true | FS_APPEND_FL on journal |
| `-lock_target` | false | FS_IMMUTABLE_FL after wipe |
| `-unlock_target_first` | true | Clear flags before wipe |
| `-print_envelope` | true | Output Base64 JSON envelope |
| `-zipkin_url` | "" | Zipkin/Jaeger collector |

## Security Model

1. **Bounded space**: Wipe in-place, no temp files, no size increase
2. **Hash chain**: `curr = SHA256(prev || before || after || identity || time)[:16]`
3. **Append-only journal**: FS_APPEND_FL prevents truncation
4. **No swap exposure**: mlock on hash buffers and wipe chunks
5. **Cache bypass**: O_DIRECT ensures disk-level persistence
6. **Filesystem fence**: Optional syncfs for full durability guarantee
7. **STRICT privilege enforcement**: If you request a privileged operation and can't deliver, the tool **fails hard** — no silent degradation

### Fail-Hard Philosophy

When you explicitly request security guarantees (`-set_append_only_journal=true`, `-lock_target=true`, `-unlock_target_first=true`), filcommit will:

- Check privileges **upfront** before any work
- **Fatal exit** if the requested operation can't be performed
- Never silently skip security-critical operations

This is intentional. Silent degradation in security tooling is dangerous. If you can't set the journal append-only, you don't have the audit guarantee you asked for — better to know immediately than discover it post-incident.

```bash
# This will FAIL if not root (good)
./filcommit -path ./data.bin -set_append_only_journal=true
# Error: set journal append-only: requires root or CAP_LINUX_IMMUTABLE (euid=1000)

# This will succeed without privileges (append-only disabled)
./filcommit -path ./data.bin -set_append_only_journal=false
```

## Requirements

- Linux kernel 2.6.22+ (for O_DIRECT, fallocate, getrandom)
- Root or `CAP_LINUX_IMMUTABLE` for FS flag manipulation
- Root or `CAP_IPC_LOCK` for mlock (or raise RLIMIT_MEMLOCK)
- ext4/xfs/btrfs for PUNCH_HOLE support

## License

MIT
