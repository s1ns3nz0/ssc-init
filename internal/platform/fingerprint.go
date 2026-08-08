package platform

// FileFingerprint is the complete filesystem identity required to trust a
// content-cache entry for a local file.
type FileFingerprint struct {
	Device, Inode uint64
	Mode          uint32
	Size          int64
	ModTimeNS     int64
	ChangeTimeNS  int64
}
