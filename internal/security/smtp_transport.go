package security

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/279814/relay-gate/internal/model"
)

// Validate checks the persisted settings and is repeated immediately before
// sending so historical or non-HTTP callers cannot select plaintext delivery.
func (c MailConfig) Validate() error {
	if c.UseSTARTTLS && c.UseSMTPS {
		return model.WrapValidation("SMTP 只能选择 STARTTLS 或 SMTPS 中的一种")
	}
	if c.Port < 1 || c.Port > 65535 {
		return model.WrapValidation("SMTP port 必须在 1–65535 之间")
	}
	if c.MinSeverity != "" && c.MinSeverity != SeverityInfo && c.MinSeverity != SeverityLow &&
		c.MinSeverity != SeverityMedium && c.MinSeverity != SeverityHigh && c.MinSeverity != SeverityCritical {
		return model.WrapValidation("SMTP min_severity 无效")
	}
	if strings.IndexFunc(c.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 ||
		strings.ContainsAny(c.Host, "/\\@?#") ||
		(strings.Contains(c.Host, ":") && net.ParseIP(c.Host) == nil) {
		return model.WrapValidation("SMTP host 必须是主机名或不带端口的 IP")
	}
	if strings.ContainsAny(c.From, "\r\n\x00") {
		return model.WrapValidation("SMTP from 不得包含控制字符")
	}
	for _, recipient := range c.Recipients {
		if strings.ContainsAny(recipient, "\r\n\x00") {
			return model.WrapValidation("SMTP recipients 不得包含控制字符")
		}
	}
	if !c.Enabled {
		return nil // An incomplete disabled draft does not send mail.
	}
	if !c.UseSTARTTLS && !c.UseSMTPS {
		return model.WrapValidation("SMTP 必须显式选择 STARTTLS 或 SMTPS")
	}
	if c.Host == "" {
		return model.WrapValidation("SMTP host 必填")
	}
	if _, err := mail.ParseAddress(c.From); err != nil {
		return model.WrapValidation("SMTP from 必须是合法邮件地址")
	}
	if len(c.Recipients) == 0 {
		return model.WrapValidation("SMTP recipients 必填")
	}
	for _, recipient := range c.Recipients {
		if _, err := mail.ParseAddress(strings.TrimSpace(recipient)); err != nil {
			return model.WrapValidation("SMTP recipients 必须是合法邮件地址列表")
		}
	}
	return nil
}

func (m *AlertMailer) doSend(cfg MailConfig, msg []byte) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	if m.send != nil {
		return m.send(addr, auth, cfg.From, cfg.Recipients, msg)
	}
	// One absolute deadline includes dial, greeting, TLS, AUTH and DATA.
	timeout := m.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	connection, err := m.dial(addr)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.Host}
	if m.tlsConfig != nil {
		tlsConfig = m.tlsConfig.Clone()
		tlsConfig.ServerName = cfg.Host
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	if cfg.UseSMTPS {
		secured := tls.Client(connection, tlsConfig)
		if err := secured.Handshake(); err != nil {
			return err
		}
		connection = secured
	}
	client, err := smtp.NewClient(connection, cfg.Host)
	if err != nil {
		return err
	}
	defer client.Close()
	if cfg.UseSTARTTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server does not offer required STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	from, _ := mail.ParseAddress(cfg.From) // validated before opening the socket
	if err := client.Mail(from.Address); err != nil {
		return err
	}
	for _, recipient := range cfg.Recipients {
		to, _ := mail.ParseAddress(strings.TrimSpace(recipient))
		if err := client.Rcpt(to.Address); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(msg); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}
