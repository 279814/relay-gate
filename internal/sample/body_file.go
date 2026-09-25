package sample

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/279814/relay-gate/internal/model"
)

// RedactBodyFile 按窗口流式脱敏 spill 文件；无命中时不改文件。
// 峰值缓冲约 SpillMemLimit + 最长 key，绝不整文件读进一个 []byte。
func RedactBodyFile(path string, keys []string) error {
	if path == "" || len(keys) == 0 {
		return nil
	}
	usable := make([]string, 0, len(keys))
	maxK := 0
	for _, k := range keys {
		if len(k) < model.MinRedactableKeyLen {
			continue
		}
		usable = append(usable, k)
		if len(k) > maxK {
			maxK = len(k)
		}
	}
	if len(usable) == 0 {
		return nil
	}
	hit, err := fileContainsAny(path, usable, maxK)
	if err != nil || !hit {
		return err
	}
	return rewriteRedactedFile(path, usable, maxK)
}

func fileContainsAny(path string, keys []string, maxK int) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	overlap := maxK - 1
	if overlap < 0 {
		overlap = 0
	}
	buf := make([]byte, SpillMemLimit())
	carry := make([]byte, 0, overlap)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			work := append(carry, buf[:n]...)
			for _, k := range keys {
				if bytes.Contains(work, []byte(k)) {
					return true, nil
				}
			}
			if len(work) > overlap {
				carry = append(carry[:0], work[len(work)-overlap:]...)
			} else {
				carry = append(carry[:0], work...)
			}
		}
		if readErr == io.EOF {
			return false, nil
		}
		if readErr != nil {
			return false, readErr
		}
	}
}

func rewriteRedactedFile(path string, keys []string, maxK int) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.CreateTemp(filepath.Dir(path), "relay-gate-sample-redact-*.tmp")
	if err != nil {
		return err
	}
	outPath := out.Name()
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(outPath)
		}
	}()

	overlap := maxK - 1
	if overlap < 0 {
		overlap = 0
	}
	buf := make([]byte, SpillMemLimit())
	carry := []byte(nil)
	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			work := RedactBodyKeys(append(carry, buf[:n]...), keys)
			if readErr == io.EOF {
				if _, err := out.Write(work); err != nil {
					return err
				}
				carry = nil
			} else if len(work) > overlap {
				if _, err := out.Write(work[:len(work)-overlap]); err != nil {
					return err
				}
				carry = append([]byte(nil), work[len(work)-overlap:]...)
			} else {
				carry = work
			}
		}
		if readErr == io.EOF {
			if len(carry) > 0 {
				if _, err := out.Write(RedactBodyKeys(carry, keys)); err != nil {
					return err
				}
			}
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(outPath, path); err != nil {
		_ = os.Remove(outPath)
		return err
	}
	ok = true
	return nil
}
