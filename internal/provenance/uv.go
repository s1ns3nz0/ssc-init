package provenance

import (
	"bytes"

	"github.com/pelletier/go-toml/v2"
)

type uvLock struct {
	Packages []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name    string         `toml:"name"`
	Version string         `toml:"version"`
	Source  map[string]any `toml:"source"`
	Sdist   *uvArtifact    `toml:"sdist"`
	Wheels  []uvArtifact   `toml:"wheels"`
}

type uvArtifact struct {
	Hash *string `toml:"hash"`
}

func parseUV(contents []byte) ([]Record, error) {
	var lock uvLock
	if err := toml.NewDecoder(bytes.NewReader(contents)).Decode(&lock); err != nil || len(lock.Packages) == 0 {
		return nil, ErrMalformed
	}
	seen := make(map[string]Record)
	for _, entry := range lock.Packages {
		hashes := make([]string, 0, len(entry.Wheels)+1)
		if entry.Sdist != nil && entry.Sdist.Hash != nil {
			hashes = append(hashes, *entry.Sdist.Hash)
		}
		for _, wheel := range entry.Wheels {
			if wheel.Hash != nil {
				hashes = append(hashes, *wheel.Hash)
			}
		}
		if _, valid := distinctPythonSHA256(hashes); !valid {
			return nil, ErrMalformed
		}
		record, ok := pythonRecord(entry.Name, entry.Version, !uvRegistrySource(entry.Source), hashes)
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

func uvRegistrySource(source map[string]any) bool {
	registry, ok := source["registry"].(string)
	return ok && registry != "" && len(source) == 1
}
