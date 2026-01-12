// Package email provides email sending functionality with pluggable providers.
package email

import "context"

// Message represents an email message to be sent.
type Message struct {
	To      string
	Subject string
	HTML    string
	Text    string // Plain text fallback
}

// Sender is the interface for email providers.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}
