package gosafe5

import (
	"context"
	"io"
	"os"
	"path/filepath"
)

// FileStore stores a snapshot in Path. The parent directory must exist. New
// files use mode 0600. Saves write and sync a temporary sibling, rename it over
// Path, then sync the directory. Atomic replacement requires filesystem support
// for atomic rename-over-existing (as on local Unix filesystems). FileStore must
// not be modified during use; it does not coordinate writers across processes.
type FileStore struct{ Path string }

func (s FileStore) Load(ctx context.Context) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return os.Open(s.Path)
}

func (s FileStore) Save(ctx context.Context, source io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	f, err := os.CreateTemp(dir, ".gosafe5-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := io.Copy(f, contextReader{ctx, source}); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), s.Path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr := d.Close()
	if err != nil {
		return err
	}
	return closeErr
}
