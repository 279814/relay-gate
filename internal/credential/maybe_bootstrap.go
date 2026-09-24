package credential

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/279814/relay-gate/internal/keyring"
)

// MaybeBootstrap runs crash-safe first-start credential generation when the
// three secrets are absent (§12.3). On a fresh data dir it prints
// ADMIN_PASSWORD, RELAY_KEYS, and ENCRYPTION_KEY once to out, then marks the
// journal displayed so later restarts never reprint.
//
// Precedence:
//   - bootstrap journal already displayed → no-op
//   - incomplete journal → resume (may reprint after crash recovery)
//   - operator set any of ENCRYPTION_KEY / RELAY_KEYS / ADMIN_PASSWORD → no-op
//     (env still wins at config.Load; do not invent a parallel set)
//   - on-disk keyring + bootstrap-credentials already usable → no-op
//   - otherwise → fresh Bootstrap.Run()
func MaybeBootstrap(dataDir string, out io.Writer) error {
	if dataDir == "" {
		return errors.New("需要 data 目录")
	}
	if out == nil {
		out = io.Discard
	}
	b := &Bootstrap{DataDir: dataDir, Out: out}
	phase, err := b.Phase()
	if err != nil {
		return err
	}
	switch phase {
	case PhaseDisplayed:
		return nil
	case PhasePrepared, PhaseCredentialsPersisted:
		_, err := b.Run()
		if errors.Is(err, ErrBootstrapComplete) {
			return nil
		}
		return err
	case "":
		if envHasAnySecret() || artifactsProvideSecrets(dataDir) {
			return nil
		}
		_, err := b.Run()
		if errors.Is(err, ErrBootstrapComplete) {
			return nil
		}
		return err
	default:
		return fmt.Errorf("未知 bootstrap 阶段 %q", phase)
	}
}

func envHasAnySecret() bool {
	if strings.TrimSpace(os.Getenv("ENCRYPTION_KEY")) != "" {
		return true
	}
	if strings.TrimSpace(os.Getenv("ADMIN_PASSWORD")) != "" {
		return true
	}
	for _, k := range strings.Split(os.Getenv("RELAY_KEYS"), ",") {
		if strings.TrimSpace(k) != "" {
			return true
		}
	}
	return false
}

func artifactsProvideSecrets(dataDir string) bool {
	_, master, err := keyring.Open(dataDir).LoadActive()
	if err != nil || strings.TrimSpace(master) == "" {
		return false
	}
	doc, err := LoadPersistedFile(dataDir)
	if err != nil {
		return false
	}
	return doc.AdminPasswordHash != "" && strings.TrimSpace(doc.RelayKey) != ""
}
