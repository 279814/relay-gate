package store

import (
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestSMTPInvalidEnabledConfigurationDoesNotChangeSavedConfigOrSecret(t *testing.T) {
	st := testStore(t)
	valid := SMTPConfig{Enabled: true, Host: "smtp.example.test", Port: 587, UseSTARTTLS: true,
		From: "relay@example.test", Recipients: "ops@example.test", MinSeverity: "high"}
	if err := st.SaveSMTPConfig(valid, "fixture-existing-password"); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := st.db.QueryRow(`SELECT password_enc FROM smtp_config WHERE singleton=1`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		change func(*SMTPConfig)
	}{
		{"missing_TLS", func(c *SMTPConfig) { c.UseSTARTTLS = false }},
		{"conflicting_TLS", func(c *SMTPConfig) { c.UseSMTPS = true }},
		{"negative_port", func(c *SMTPConfig) { c.Port = -1 }},
		{"port_overflow", func(c *SMTPConfig) { c.Port = 65536 }},
		{"host_header_injection", func(c *SMTPConfig) { c.Host = "smtp.example.test\r\nprivate" }},
		{"host_internal_tab", func(c *SMTPConfig) { c.Host = "smtp\t.example.test" }},
		{"host_fragment", func(c *SMTPConfig) { c.Host = "smtp.example.test#fragment" }},
		{"sender_header_injection", func(c *SMTPConfig) { c.From = "relay@example.test\r\nBcc: private@example.test" }},
		{"invalid_recipient", func(c *SMTPConfig) { c.Recipients = "not-a-mailbox" }},
		{"unknown_severity", func(c *SMTPConfig) { c.MinSeverity = "urgent" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			input := valid
			c.change(&input)
			if err := st.SaveSMTPConfig(input, "fixture-replacement-password"); !errors.Is(err, model.ErrValidation) {
				t.Fatalf("invalid configuration was not rejected: %v", err)
			}
			current, err := st.GetSMTPConfig()
			if err != nil {
				t.Fatal(err)
			}
			if current.Host != valid.Host || current.Port != valid.Port || !current.UseSTARTTLS || current.UseSMTPS || current.From != valid.From || current.Recipients != valid.Recipients || current.MinSeverity != valid.MinSeverity {
				t.Fatal("rejected save changed SMTP configuration")
			}
			var after string
			if err := st.db.QueryRow(`SELECT password_enc FROM smtp_config WHERE singleton=1`).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Fatal("rejected save changed encrypted SMTP password")
			}
		})
	}
}
