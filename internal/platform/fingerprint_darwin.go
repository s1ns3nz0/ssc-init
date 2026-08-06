//go:build darwin

package platform

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Fingerprint returns the local filesystem identity used to validate a cache
// entry. Darwin supplies ctime with nanosecond precision through Stat_t.
func Fingerprint(info os.FileInfo) (FileFingerprint, bool) {
	if info == nil {
		return FileFingerprint{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return FileFingerprint{}, false
	}
	return FileFingerprint{
		Device:       uint64(stat.Dev),
		Inode:        stat.Ino,
		Mode:         uint32(stat.Mode),
		Size:         stat.Size,
		ModTimeNS:    info.ModTime().UnixNano(),
		ChangeTimeNS: stat.Ctimespec.Sec*1_000_000_000 + stat.Ctimespec.Nsec,
	}, true
}

func localFilesystem(fd uintptr) (local bool, known bool) {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(fd), &stat); err != nil {
		return false, false
	}
	switch statfsTypeName(stat) {
	case "apfs", "exfat", "hfs", "msdos", "ufs", "zfs":
		return true, true
	case "afpfs", "fusefs", "nfs", "smbfs", "webdav":
		return false, true
	default:
		return false, false
	}
}

func statfsTypeName(stat unix.Statfs_t) string {
	name := make([]byte, 0, len(stat.Fstypename))
	for _, value := range stat.Fstypename {
		if value == 0 {
			break
		}
		name = append(name, byte(value))
	}
	return string(name)
}
