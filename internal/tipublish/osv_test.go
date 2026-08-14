package tipublish

import (
	"strings"
	"testing"
)

type byteCountingReader struct {
	reader *strings.Reader
	read   int
}

func (reader *byteCountingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.read += count
	return count, err
}

func TestReadOSVStopsStreamingBeforeArrayAmplification(t *testing.T) {
	document := `[` + strings.Repeat(`{},`, 10_000) + `{}` + `]`
	reader := &byteCountingReader{reader: strings.NewReader(document)}
	_, _, err := readOSVReader(reader, decodedBudget{elements: 3, stringBytes: 1024})
	if err == nil || !strings.Contains(err.Error(), "decoded element budget") {
		t.Fatalf("error=%v, want decoded element budget", err)
	}
	if reader.read >= len(document) {
		t.Fatalf("reader consumed complete %d-byte array before rejection", len(document))
	}
}
