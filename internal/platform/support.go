package platform

// OperationallySupported reports whether SSC Init may inspect host state on goos.
func OperationallySupported(goos string) bool {
	return goos == "darwin"
}
