package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const cacheTTL = 1 * time.Hour

// FileCache stores fetched action/workflow files on disk.
type FileCache struct {
	dir string
}

// NewFileCache creates a cache in ~/.cache/abom/ (or XDG_CACHE_HOME/abom/).
func NewFileCache() (*FileCache, error) {
	dir := os.Getenv("XDG_CACHE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("determining home directory: %w", err)
		}
		dir = filepath.Join(home, ".cache")
	}
	dir = filepath.Join(dir, "abom")

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}

	return &FileCache{dir: dir}, nil
}

// Get retrieves a cached file. Returns nil if not cached or expired.
// SHA-pinned refs never expire; tag/branch refs expire after cacheTTL.
func (c *FileCache) Get(owner, repo, ref, path string, isSHA bool) ([]byte, error) {
	fp := c.path(owner, repo, ref, path)

	info, err := os.Stat(fp)
	if err != nil {
		return nil, err
	}

	// SHA refs are immutable — never expire
	if !isSHA && time.Since(info.ModTime()) > cacheTTL {
		return nil, fmt.Errorf("cache expired")
	}

	return os.ReadFile(fp)
}

// Put stores content in the cache.
func (c *FileCache) Put(owner, repo, ref, path string, content []byte) error {
	fp := c.path(owner, repo, ref, path)

	dir := filepath.Dir(fp)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	return os.WriteFile(fp, content, 0o600)
}

func (c *FileCache) path(owner, repo, ref, path string) string {
	// Hash the path component to avoid filesystem issues
	h := sha256.Sum256([]byte(path))
	pathHash := hex.EncodeToString(h[:8])
	return filepath.Join(c.dir, owner, repo, ref, pathHash+".yml")
}
