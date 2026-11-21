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
	"strings"
	"sync"

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
	// pathSecret prefixes every URL (/s/<pathSecret>/...), and the session
	// cookie is scoped to that path. Browsers send cookies to every port on a
	// host, so without it any other local server the operator visits (a dev
	// server, a container's published port) would receive the cookie.
	pathSecret string
	token      string // the start URL's token, exchangeable once for the session
	session    string // the session cookie's value
	csrf       string // required on every POST

	mu        sync.Mutex
	tokenUsed bool
}

// New makes a panel for store, which is the database target describes, on
// port (the real one: it is in the allowed Host and the start URL).
func New(s *store.Store, t internal.Target, port int) (*Server, error) {
	if port <= 0 {
		return nil, fmt.Errorf("ui: port must be the listener's actual port, got %d", port)
	}
	srv := &Server{store: s, target: t, port: port}
	for _, v := range []*string{&srv.pathSecret, &srv.token, &srv.session, &srv.csrf} {
		tok, err := randomToken()
		if err != nil {
			return nil, err
		}
		*v = tok
	}
	return srv, nil
}

// base is the path every page lives under, with a trailing slash.
func (s *Server) base() string { return "/s/" + s.pathSecret + "/" }

// url turns a panel-relative path ("clients", "client?id=...") into an
// absolute one, for redirects.
func (s *Server) url(rel string) string { return s.base() + rel }

// StartURL is the URL to open: it carries the one-time token.
func (s *Server) StartURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d%s?token=%s", s.port, s.base(), url.QueryEscape(s.token))
}

// Handler is the panel, with protect around all of it.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Route(strings.TrimSuffix(s.base(), "/"), func(r chi.Router) {
		r.Get("/assets/style.css", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			_, _ = w.Write(assets.StyleCSS)
		})
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, s.url("clients"), http.StatusSeeOther)
		})
		s.clientRoutes(r)
		s.resourceRoutes(r)
	})
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
		Base: s.base(),
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
