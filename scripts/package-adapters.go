//go:build ignore

package main

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

var fixedTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

func main() {
	if len(os.Args) != 3 {
		fail("usage: package-adapters <adapters-dir> <dist-dir>")
	}
	for _, host := range []string{"claude", "codex", "cursor"} {
		if err := packageHost(os.Args[1], os.Args[2], host); err != nil {
			fail("package %s adapter: %v", host, err)
		}
	}
}

func packageHost(adapters, dist, host string) error {
	root := filepath.Join(adapters, host)
	var files []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 {
			return fmt.Errorf("unsafe package entry %q", entry.Name())
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)
	if len(files) == 0 {
		return fmt.Errorf("empty package")
	}
	name := filepath.Join(dist, "ssc-init-adapter-"+host+".zip")
	temporary := name + ".tmp"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	clean := false
	defer func() {
		_ = file.Close()
		if !clean {
			_ = os.Remove(temporary)
		}
	}()
	writer := zip.NewWriter(file)
	for _, path := range files {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		header := &zip.FileHeader{Name: filepath.ToSlash(filepath.Join("ssc-init-"+host, relative)), Method: zip.Deflate}
		header.SetModTime(fixedTime)
		header.SetMode(0o644)
		output, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := input.Close()
		if copyErr != nil || closeErr != nil {
			return fmt.Errorf("copy package entry")
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, name); err != nil {
		return err
	}
	clean = true
	return nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
