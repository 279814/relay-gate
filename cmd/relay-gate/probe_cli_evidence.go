package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"sync"
)

// Only bytes consumed by the shared transport/Executor are hashed. A probe
// intentionally stops early, so this never claims a complete response body.
type cliPrefixHash struct {
	mu   sync.Mutex
	hash hash.Hash
}

func newCLIPrefixHash(key []byte, domain string) *cliPrefixHash {
	digest := hmac.New(sha256.New, key)
	digest.Write([]byte(domain + "\x00"))
	return &cliPrefixHash{hash: digest}
}

func (digest *cliPrefixHash) add(data []byte) {
	digest.mu.Lock()
	digest.hash.Write(data)
	digest.mu.Unlock()
}
func (digest *cliPrefixHash) sum() string {
	digest.mu.Lock()
	defer digest.mu.Unlock()
	return hex.EncodeToString(digest.hash.Sum(nil))
}

type cliHashingBody struct {
	io.ReadCloser
	digest *cliPrefixHash
}

func (body cliHashingBody) Read(buffer []byte) (int, error) {
	count, err := body.ReadCloser.Read(buffer)
	if count > 0 {
		body.digest.add(buffer[:count])
	}
	return count, err
}

type cliAttemptEvidence struct{ request, response *cliPrefixHash }

func (transports *cliProbeTransports) evidence() (request, response string) {
	if transports.last == nil {
		return "", ""
	}
	request = transports.last.request.sum()
	if transports.last.response != nil {
		response = transports.last.response.sum()
	}
	return
}
