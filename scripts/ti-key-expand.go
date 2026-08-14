//go:build ignore

package main

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	seed, err := io.ReadAll(io.LimitReader(os.Stdin, ed25519.SeedSize+1))
	if err != nil || len(seed) != ed25519.SeedSize {
		os.Exit(1)
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	if err := writePrivateExclusive(os.Args[1], key); err != nil {
		fmt.Fprintln(os.Stderr, "private key cannot be written")
		os.Exit(1)
	}
}

func writePrivateExclusive(path string, key []byte) (result error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("unsafe path")
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return fmt.Errorf("unsafe parent")
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe parent")
	}
	if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
		return fmt.Errorf("target exists")
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(key); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}
