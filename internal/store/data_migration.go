package store

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type encryptedStateExecutor interface {
	encryptedStateQuery
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// SQLite's substr operates on a BLOB explicitly: concatenation in historical
// spill writes could otherwise make SQLite count UTF-8 characters instead.
type sampleBlobReader struct {
	ctx               context.Context
	q                 encryptedStateQuery
	table, column     string
	id, offset, total int64
}

func (r *sampleBlobReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if r.offset >= r.total {
		return 0, io.EOF
	}
	n := min(int64(len(dst)), r.total-r.offset)
	var raw []byte
	err := r.q.QueryRowContext(r.ctx, `SELECT substr(CAST(`+r.column+` AS BLOB),?,?) FROM `+r.table+` WHERE id=?`, r.offset+1, n, r.id).Scan(&raw)
	if err != nil {
		return 0, err
	}
	if len(raw) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	copy(dst, raw)
	r.offset += int64(len(raw))
	return len(raw), nil
}

type legacyMultipartReader struct {
	c      *Cipher
	src    *bufio.Reader
	keyID  string
	plain  []byte
	frames int
}

func newLegacyMultipartReader(c *Cipher, src io.Reader) (*legacyMultipartReader, error) {
	r := bufio.NewReaderSize(src, 512)
	header, err := r.ReadSlice('\n')
	if err != nil || len(header) > 128 {
		return nil, errors.New("旧分块样本信封头无效")
	}
	parts := strings.Split(strings.TrimSuffix(string(header), "\n"), ":")
	if len(parts) != 3 || parts[0] != "v1m" || parts[1] == "" || parts[2] != "" {
		return nil, errors.New("旧分块样本信封身份无效")
	}
	return &legacyMultipartReader{c: c, src: r, keyID: parts[1]}, nil
}

func (r *legacyMultipartReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if len(r.plain) == 0 {
		var length [4]byte
		if _, err := io.ReadFull(r.src, length[:]); err != nil {
			if err == io.EOF && r.frames == 0 {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		n := binary.BigEndian.Uint32(length[:])
		if n == 0 || n > 2*dataChunkLimit {
			return 0, errors.New("旧分块样本帧长度无效")
		}
		frame := make([]byte, int(n))
		if _, err := io.ReadFull(r.src, frame); err != nil {
			return 0, err
		}
		if !bytes.HasPrefix(frame, []byte("v1:"+r.keyID+":")) {
			return 0, errors.New("旧分块样本帧身份无效")
		}
		plain, err := r.c.DecryptEnvelope(string(frame))
		if err != nil {
			return 0, errors.New("旧分块样本帧认证失败")
		}
		r.plain = []byte(plain)
		if len(r.plain) == 0 {
			return 0, errors.New("旧分块样本空帧无效")
		}
		r.frames++
	}
	n := copy(dst, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

type bodyColumn struct{ table, column, purpose string }

var sensitiveBodyColumns = []bodyColumn{
	{"sample_request", "in_body", sampleKeyPurpose},
	{"sample_attempt", "out_body", sampleKeyPurpose},
	{"sample_attempt", "resp_body", sampleKeyPurpose},
}

// walkSensitiveBodies retains only one row's metadata and one frame at a time.
// All table/column identifiers below are compile-time literals.
func walkSensitiveBodies(ctx context.Context, q encryptedStateQuery, fn func(bodyColumn, int64, int64) error) error {
	for _, col := range sensitiveBodyColumns {
		var cursor int64
		for {
			var id, total int64
			err := q.QueryRowContext(ctx, `SELECT id,COALESCE(length(CAST(`+col.column+` AS BLOB)),0) FROM `+col.table+` WHERE id>? ORDER BY id LIMIT 1`, cursor).Scan(&id, &total)
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			if err != nil {
				return err
			}
			if total > 0 {
				if err := fn(col, id, total); err != nil {
					return fmt.Errorf("%s id=%d %s: %w", col.table, id, col.column, err)
				}
			}
			cursor = id
		}
	}
	return nil
}

func migrateSampleDataBodies(ctx context.Context, q encryptedStateExecutor, c *Cipher) error {
	return walkSensitiveBodies(ctx, q, func(col bodyColumn, id, total int64) error {
		reader := func() *sampleBlobReader {
			return &sampleBlobReader{ctx: ctx, q: q, table: col.table, column: col.column, id: id, total: total}
		}
		var prefix []byte
		if err := q.QueryRowContext(ctx, `SELECT substr(CAST(`+col.column+` AS BLOB),1,4) FROM `+col.table+` WHERE id=?`, id).Scan(&prefix); err != nil {
			return err
		}
		if bytes.HasPrefix(prefix, []byte("v2:")) || bytes.Equal(prefix, []byte("v2m:")) {
			return validateSensitiveBody(c, col.purpose, reader())
		}
		var plain io.Reader = reader()
		plainSize := total
		if bytes.Equal(prefix, []byte("v1m:")) {
			legacy, err := newLegacyMultipartReader(c, reader())
			if err != nil {
				return err
			}
			plainSize, err = io.Copy(io.Discard, legacy)
			if err != nil {
				return err
			}
			plain, err = newLegacyMultipartReader(c, reader())
			if err != nil {
				return err
			}
		} else if bytes.HasPrefix(prefix, []byte("v1:")) {
			// GCM's historical single-message format requires the complete one
			// envelope for authentication; multipart history stays frame-bounded.
			raw, err := io.ReadAll(reader())
			if err != nil {
				return err
			}
			value, err := c.DecryptEnvelope(string(raw))
			if err != nil {
				return errors.New("旧样本信封认证失败")
			}
			plain = strings.NewReader(value)
			plainSize = int64(len(value))
			if strings.HasPrefix(value, "v1m:") {
				// Repair the old startup bug which encrypted a valid v1m object
				// as if it were the plaintext response. Authenticate every inner
				// frame before treating it as the historical multipart encoding.
				legacy, err := newLegacyMultipartReader(c, strings.NewReader(value))
				if err != nil {
					return err
				}
				plainSize, err = io.Copy(io.Discard, legacy)
				if err != nil {
					return err
				}
				plain, err = newLegacyMultipartReader(c, strings.NewReader(value))
				if err != nil {
					return err
				}
			}
		}
		if plainSize == 0 {
			_, err := q.ExecContext(ctx, `UPDATE `+col.table+` SET `+col.column+`=zeroblob(0) WHERE id=?`, id)
			return err
		}
		file, err := os.CreateTemp("", "relay-data-key-migration-*.enc")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		defer file.Close()
		if plainSize <= dataChunkLimit {
			value, err := io.ReadAll(plain)
			if err != nil {
				return err
			}
			encoded, err := c.encryptDataBlob(col.purpose, value)
			if err != nil {
				return err
			}
			if _, err := file.Write(encoded); err != nil {
				return err
			}
		} else if err := encryptDataStream(c, col.purpose, file, plain, plainSize, dataChunkLimit); err != nil {
			return err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		buf := make([]byte, dataChunkLimit)
		first := true
		for {
			n, rerr := file.Read(buf)
			if n > 0 {
				query := `UPDATE ` + col.table + ` SET ` + col.column + `=? WHERE id=?`
				if !first {
					query = `UPDATE ` + col.table + ` SET ` + col.column + `=CAST(` + col.column + ` AS BLOB)||? WHERE id=?`
				}
				if _, err := q.ExecContext(ctx, query, buf[:n], id); err != nil {
					return err
				}
				first = false
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return rerr
			}
		}
		return nil
	})
}

func validateSensitiveBody(c *Cipher, purpose string, src io.Reader) error {
	reader := bufio.NewReader(src)
	prefix, err := reader.Peek(4)
	if err != nil && err != io.EOF {
		return err
	}
	if bytes.Equal(prefix, []byte("v2m:")) {
		return decryptDataStream(c, purpose, io.Discard, reader)
	}
	raw, err := io.ReadAll(io.LimitReader(reader, 2*dataChunkLimit+1))
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > 2*dataChunkLimit {
		return errors.New("非分块 Data Key 信封超过单帧上限")
	}
	if !bytes.HasPrefix(raw, []byte("v2:")) {
		return errors.New("schema 8 正文缺少 Data Key 信封")
	}
	_, err = c.decryptDataBlob(purpose, raw)
	return err
}
