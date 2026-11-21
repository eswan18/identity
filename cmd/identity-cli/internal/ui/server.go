// Package ui is identity-cli's local admin panel: server-rendered pages for
// OAuth clients and resources, served on 127.0.0.1 to the operator who ran
// `identity-cli ui`. Every change goes through package ops, the same code the
// CLI commands use; this package only renders forms and turns them into ops
// calls.
package ui

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/cmd/identity-cli/internal/ui/assets"
	"github.com/eswan18/identity/cmd/identity-cli/internal/ui/views"
	"github.com/eswan18/identity/pkg/store"
	"github.com/go-chi/chi/v5"
)

// Server is one panel session against one database.
type Server struct {
	store  *store.Store
	target internal.Target
	port   int
	token  string // the start URL's one-time token, then the session cookie
	csrf   string // required on every POST
}

// New makes a panel for store, which is the database target describes.
func New(s *store.Store, t internal.Target, port int) (*Server, error) {
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &Server{store: s, target: t, port: port, token: token, csrf: csrf}, nil
}

// StartURL is the URL to open: it carries the one-time token.
func (s *Server) StartURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/?token=%s", s.port, url.QueryEscape(s.token))
}

// Handler is the panel, with protect around all of it.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Get("/assets/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(assets.StyleCSS)
	})
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/clients", http.StatusSeeOther)
	})
	s.clientRoutes(r)
	s.resourceRoutes(r)
	return s.protect(r)
}

// page is what every view needs from the server.
func (s *Server) page(title string) views.Page {
	return views.Page{
		Title: title,
		Env: views.EnvBanner{
			Label:  s.envLabel(),
			Prod:   s.target.IsProd(),
			Custom: s.target.Name == "custom",
		},
		CSRF: s.csrf,
	}
}

func (s *Server) envLabel() string {
	switch s.target.Name {
	case "prod":
		return "PROD"
	case "staging":
		return "STAGING"
	default:
		return "CUSTOM: " + s.target.Host()
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
