//go:build !darwin

package platform

import "os"

// Fingerprint is intentionally unavailable outside Darwin. Cache callers must
// rehash rather than accepting a weaker identity contract on those platforms.
func Fingerprint(os.FileInfo) (FileFingerprint, bool) {
	return FileFingerprint{}, false
}

func localFilesystem(uintptr) (local bool, known bool) {
	return false, false
}
