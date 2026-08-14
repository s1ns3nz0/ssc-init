package tikey

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type linkIdentity struct {
	parentFD int
	name     string
	dev      uint64
	ino      uint64
}

// WritePrivateExclusive anchors every lookup at an already-open directory.
// beforeWalk exists only for synchronized adversarial tests; production passes nil.
func WritePrivateExclusive(path string, key []byte, beforeWalk func()) (result error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(key) == 0 {
		return fmt.Errorf("unsafe path")
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) < 2 {
		return fmt.Errorf("unsafe path")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("unsafe path")
		}
	}
	if beforeWalk != nil {
		beforeWalk()
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	fds := []int{rootFD}
	defer func() {
		for index := len(fds) - 1; index >= 0; index-- {
			_ = unix.Close(fds[index])
		}
	}()
	links := make([]linkIdentity, 0, len(parts)-1)
	current := rootFD
	for _, component := range parts[:len(parts)-1] {
		child, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return openErr
		}
		var stat unix.Stat_t
		if err := unix.Fstat(child, &stat); err != nil {
			_ = unix.Close(child)
			return err
		}
		links = append(links, linkIdentity{current, component, uint64(stat.Dev), stat.Ino})
		fds = append(fds, child)
		current = child
	}
	if !linksStable(links) {
		return fmt.Errorf("path changed")
	}
	name := parts[len(parts)-1]
	fd, err := unix.Openat(current, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = unix.Unlinkat(current, name, 0)
		}
	}()
	if !linksStable(links) {
		return fmt.Errorf("path changed")
	}
	if _, err := file.Write(key); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if !linksStable(links) {
		return fmt.Errorf("path changed")
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func linksStable(links []linkIdentity) bool {
	for _, link := range links {
		var stat unix.Stat_t
		if err := unix.Fstatat(link.parentFD, link.name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(stat.Dev) != link.dev || stat.Ino != link.ino {
			return false
		}
	}
	return true
}
