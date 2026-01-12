package email

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
)

func TestLogSender_Send(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil) // Reset after test

	sender := NewLogSender()

	msg := Message{
		To:      "test@example.com",
		Subject: "Test Subject",
		HTML:    "<h1>Hello</h1>",
		Text:    "Hello",
	}

	err := sender.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("LogSender.Send failed: %v", err)
	}

	output := buf.String()

	// Verify log contains email details
	if !strings.Contains(output, "test@example.com") {
		t.Error("Log output should contain recipient email")
	}
	if !strings.Contains(output, "Test Subject") {
		t.Error("Log output should contain subject")
	}
	if !strings.Contains(output, "Hello") {
		t.Error("Log output should contain message text")
	}
	if !strings.Contains(output, "EMAIL (dev mode") {
		t.Error("Log output should indicate dev mode")
	}
}

func TestMessage_Fields(t *testing.T) {
	msg := Message{
		To:      "recipient@example.com",
		Subject: "Important Subject",
		HTML:    "<p>HTML content</p>",
		Text:    "Plain text content",
	}

	if msg.To != "recipient@example.com" {
		t.Errorf("expected To=%q, got %q", "recipient@example.com", msg.To)
	}
	if msg.Subject != "Important Subject" {
		t.Errorf("expected Subject=%q, got %q", "Important Subject", msg.Subject)
	}
	if msg.HTML != "<p>HTML content</p>" {
		t.Errorf("expected HTML=%q, got %q", "<p>HTML content</p>", msg.HTML)
	}
	if msg.Text != "Plain text content" {
		t.Errorf("expected Text=%q, got %q", "Plain text content", msg.Text)
	}
}
