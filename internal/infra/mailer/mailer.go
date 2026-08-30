// Package mailer sends transactional emails. The console driver logs the
// message (development, paired with mailhog in docker-compose for SMTP).
package mailer

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/flametest/access-hub/internal/config"
	"github.com/flametest/vita/verrors"
	log "github.com/flametest/vita/vlog"
)

// Mailer sends plain-text emails asynchronously-safe (implementations must be
// safe for concurrent use).
type Mailer interface {
	// Send delivers textBody to a single recipient.
	Send(ctx context.Context, to, subject, textBody string) error
}

// NewMailer builds the configured driver ("console" or "smtp").
func NewMailer(cfg *config.MailerConfig) (Mailer, error) {
	switch cfg.Driver {
	case config.MailerDriverConsole:
		return NewConsoleMailer(), nil
	case config.MailerDriverSMTP:
		return NewSMTPMailer(cfg.SMTP), nil
	default:
		return nil, verrors.InternalServerError(fmt.Sprintf("unknown mailer driver %q", cfg.Driver))
	}
}

// ConsoleMailer logs outgoing mail instead of delivering it (development).
type ConsoleMailer struct{}

var _ Mailer = (*ConsoleMailer)(nil)

// NewConsoleMailer returns the logging mailer.
func NewConsoleMailer() *ConsoleMailer { return &ConsoleMailer{} }

func (m *ConsoleMailer) Send(_ context.Context, to, subject, textBody string) error {
	log.Info().
		Any("to", to).
		Any("subject", subject).
		Msgf("mailer[console] sending email:\n%s", textBody)
	return nil
}

// SMTPMailer delivers via net/smtp (HELO local; AUTH PLAIN when a username is
// configured — mailhog and most relays accept unauthenticated local mail).
type SMTPMailer struct {
	addr string
	auth smtp.Auth
	from string
}

var _ Mailer = (*SMTPMailer)(nil)

// NewSMTPMailer builds the SMTP mailer from configuration.
func NewSMTPMailer(cfg config.SMTPConfig) *SMTPMailer {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	return &SMTPMailer{addr: addr, auth: auth, from: cfg.From}
}

func (m *SMTPMailer) Send(_ context.Context, to, subject, textBody string) error {
	if m.from == "" {
		return verrors.InternalServerError("smtp mailer: empty from address")
	}
	msg := buildMessage(m.from, to, subject, textBody)
	if err := smtp.SendMail(m.addr, m.auth, m.from, []string{to}, msg); err != nil {
		return verrors.Wrap(err, fmt.Sprintf("smtp send to %s", to))
	}
	return nil
}

// buildMessage renders a minimal RFC 5322 plain-text message.
func buildMessage(from, to, subject, textBody string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(textBody, "\n", "\r\n"))
	b.WriteString("\r\n")
	return []byte(b.String())
}
