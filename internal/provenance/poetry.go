package provenance

import (
	"bytes"

	"github.com/pelletier/go-toml/v2"
)

type poetryLock struct {
	Packages []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name    string        `toml:"name"`
	Version string        `toml:"version"`
	Develop bool          `toml:"develop"`
	Source  *poetrySource `toml:"source"`
	Files   []poetryFile  `toml:"files"`
}

type poetrySource struct {
	Type string `toml:"type"`
}

type poetryFile struct {
	Hash *string `toml:"hash"`
}

func parsePoetry(contents []byte) ([]Record, error) {
	var lock poetryLock
	if err := toml.NewDecoder(bytes.NewReader(contents)).Decode(&lock); err != nil || len(lock.Packages) == 0 {
		return nil, ErrMalformed
	}
	seen := make(map[string]Record)
	for _, entry := range lock.Packages {
		hashes := make([]string, 0, len(entry.Files))
		for _, file := range entry.Files {
			if file.Hash != nil {
				hashes = append(hashes, *file.Hash)
			}
		}
		mutable := entry.Develop || entry.Source != nil && entry.Source.Type != "legacy"
		record, ok := pythonRecord(entry.Name, entry.Version, mutable, hashes)
		if !ok {
			return nil, ErrMalformed
		}
		if err := addRecord(seen, record); err != nil {
			return nil, err
		}
	}
	records := make([]Record, 0, len(seen))
	for _, record := range seen {
		records = append(records, record)
	}
	return records, nil
}
