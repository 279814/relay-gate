package store

// BackupManifest is the durable pairing contract for one schema boundary.
// It deliberately contains only non-secret identifiers and backup evidence.
type BackupManifest struct {
	FormatVersion     int    `json:"format_version"`
	SourceSchema      int    `json:"source_schema"`
	SourceVariant     string `json:"source_variant,omitempty"`
	SourceFingerprint string `json:"source_fingerprint"`
	TargetSchema      int    `json:"target_schema"`
	DatabaseFile      string `json:"database_file"`
	DatabaseSize      int64  `json:"database_size"`
	DatabaseSHA256    string `json:"database_sha256"`
	LegacyCipherID    string `json:"legacy_cipher_id"`
	SourceValidator   string `json:"source_validator"`
	PairedBuildID     string `json:"paired_build_id"`
	ReaderContract    string `json:"reader_contract"`
	CreatedAt         string `json:"created_at"`
}
