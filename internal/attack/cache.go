package attack

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// LoadUpdateMeta reads the validators used for conditional dataset requests.
func LoadUpdateMeta(path string) (UpdateMeta, error) {
	var m UpdateMeta
	if err := loadJSON(path, &m); err != nil {
		return UpdateMeta{}, err
	}
	return m, nil
}

// SaveUpdateMeta replaces the metadata file after a complete write.
func SaveUpdateMeta(path string, m UpdateMeta) error {
	return saveJSON(path, m)
}

// SaveCacheData writes the normalized cache using the existing JSON schema.
func SaveCacheData(path string, cache CacheData) error {
	return saveJSON(path, cache)
}

// LoadCacheData reads a normalized cache without selecting a matrix or printing.
func LoadCacheData(path string) (CacheData, error) {
	var cache CacheData
	if err := loadJSON(path, &cache); err != nil {
		return CacheData{}, err
	}

	return cache, nil
}

func loadJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func saveJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, func(file *os.File) error {
		_, err := file.Write(data)
		return err
	})
}

func writeFileAtomic(path string, write func(*os.File) error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Use the destination directory so rename stays on the same filesystem.
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()

	if err := file.Chmod(0o644); err != nil {
		return err
	}
	if err := write(file); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
