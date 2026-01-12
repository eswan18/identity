package email

import (
	"context"
	"fmt"

	"github.com/resend/resend-go/v2"
)

// ResendSender sends emails using the Resend API.
type ResendSender struct {
	client *resend.Client
	from   string
}

// NewResendSender creates a new Resend email sender.
func NewResendSender(apiKey, from string) *ResendSender {
	return &ResendSender{
		client: resend.NewClient(apiKey),
		from:   from,
	}
}

// Send sends an email using the Resend API.
func (s *ResendSender) Send(ctx context.Context, msg Message) error {
	params := &resend.SendEmailRequest{
		From:    s.from,
		To:      []string{msg.To},
		Subject: msg.Subject,
		Html:    msg.HTML,
		Text:    msg.Text,
	}

	_, err := s.client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("resend: failed to send email: %w", err)
	}

	return nil
}
