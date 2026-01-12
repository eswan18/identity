package email

import (
	"context"
	"log"
)

// LogSender logs emails to stdout instead of sending them.
// Useful for development and testing.
type LogSender struct{}

// NewLogSender creates a new log-based email sender.
func NewLogSender() *LogSender {
	return &LogSender{}
}

// Send logs the email details to stdout.
func (s *LogSender) Send(ctx context.Context, msg Message) error {
	log.Printf(`
================================================================================
EMAIL (dev mode - not actually sent)
================================================================================
To:      %s
Subject: %s
--------------------------------------------------------------------------------
%s
================================================================================
`, msg.To, msg.Subject, msg.Text)
	return nil
}
