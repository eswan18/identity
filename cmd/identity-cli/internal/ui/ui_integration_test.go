//go:build integration

package ui

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/eswan18/identity/cmd/identity-cli/internal"
	"github.com/eswan18/identity/cmd/identity-cli/internal/ops"
	"github.com/eswan18/identity/db/migrations"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/store"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func newDB(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:17",
		postgres.WithDatabase("identity"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		postgres.BasicWaitStrategies(),
		postgres.WithSQLDriver("pgx"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pg.Terminate(context.Background()) })
	dbURL, err := pg.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	require.NoError(t, migrations.Up(dbURL))
	s, err := store.New(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.DB.Close() })
	return s
}

// panel is a signed-in browser session against a panel.
type panel struct {
	t      *testing.T
	srv    *Server
	h      http.Handler
	cookie *http.Cookie
}

func newPanel(t *testing.T, s *store.Store, env string) *panel {
	t.Helper()
	srv, err := New(s, internal.Target{Name: env, Source: "test", URL: "postgres://h.example/db"}, 8765)
	require.NoError(t, err)
	p := &panel{t: t, srv: srv, h: srv.Handler()}
	rec := p.send("GET", "/?token="+url.QueryEscape(srv.token), nil)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	p.cookie = rec.Result().Cookies()[0]
	return p
}

func (p *panel) send(method, target string, form url.Values) *httptest.ResponseRecorder {
	p.t.Helper()
	var body io.Reader = strings.NewReader("")
	if form != nil {
		form.Set("csrf", p.srv.csrf)
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	req.Host = "127.0.0.1:8765"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if p.cookie != nil {
		req.AddCookie(p.cookie)
	}
	rec := httptest.NewRecorder()
	p.h.ServeHTTP(rec, req)
	return rec
}

func (p *panel) get(target string) string {
	p.t.Helper()
	rec := p.send("GET", target, nil)
	require.Equal(p.t, http.StatusOK, rec.Code, rec.Body.String())
	return rec.Body.String()
}

var hiddenRE = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)"`)

// hiddenFields returns the hidden inputs of the page's form with action
// containing actionPart, as a form to post back.
func hiddenFields(t *testing.T, page, actionPart string) url.Values {
	t.Helper()
	i := strings.Index(page, `action="`+actionPart)
	require.GreaterOrEqual(t, i, 0, "no form posting to %s in:\n%s", actionPart, page)
	end := strings.Index(page[i:], "</form>")
	form := url.Values{}
	for _, m := range hiddenRE.FindAllStringSubmatch(page[i:i+end], -1) {
		if m[1] == "csrf" {
			continue
		}
		form.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return form
}

func clientURL(path, id string) string { return path + "?id=" + url.QueryEscape(id) }

func editForm(d ops.ClientDetail) url.Values {
	f := url.Values{
		"name":             {d.Client.Name},
		"redirect_uris":    {strings.Join(d.Client.RedirectUris, "\n")},
		"scopes":           {strings.Join(d.Client.AllowedScopes, " ")},
		"default_resource": {d.Client.DefaultResource.String},
		"fingerprint":      {d.Fingerprint()},
	}
	for _, r := range d.Resources {
		f.Add("resources", r.Uri)
	}
	if d.Client.Trusted {
		f.Set("trusted", "on")
	}
	return f
}

func TestCLIUI(t *testing.T) {
	s := newDB(t)
	ctx := context.Background()
	p := newPanel(t, s, "staging")
	const resA = "https://a.example.com/mcp"
	_, err := ops.CreateResource(ctx, s, resA, "A", map[string]string{"a:read": "Read A"}, false)
	require.NoError(t, err)

	t.Run("ListShowsStagingBanner", func(t *testing.T) {
		page := p.get("/clients")
		require.Contains(t, page, "STAGING")
		require.NotContains(t, page, "[PROD]")
	})

	t.Run("ClientEditFlow", func(t *testing.T) {
		c, _, err := ops.CreateClient(ctx, s, ops.ClientCreate{Name: "Edit Me",
			RedirectURIs: []string{"https://e.example/1", "https://e.example/2"}, Scopes: []string{"openid"}})
		require.NoError(t, err)
		id := c.Client.ClientID
		require.Contains(t, p.get(clientURL("/client", id)), "Edit Me")
		copyID := `data-copy="` + html.EscapeString(id) + `"`
		require.Contains(t, p.get(clientURL("/client", id)), copyID, "client page has a copy button for the client ID")
		require.Contains(t, p.get("/clients"), copyID, "list has a copy button for the client ID")

		form := editForm(c)
		form.Set("name", "Edited")
		form.Set("redirect_uris", "https://e.example/2\n\n  ") // drop /1; blank lines ignored
		rec := p.send("POST", clientURL("/client/review", id), form)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		review := rec.Body.String()
		require.Contains(t, review, "Edited")
		require.Contains(t, review, "https://e.example/1", "the removed URI is shown")
		got, err := ops.GetClient(ctx, s, id)
		require.NoError(t, err)
		require.Equal(t, "Edit Me", got.Client.Name, "review writes nothing")

		rec = p.send("POST", clientURL("/client/apply", id), hiddenFields(t, review, "/client/apply"))
		require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
		got, err = ops.GetClient(ctx, s, id)
		require.NoError(t, err)
		require.Equal(t, "Edited", got.Client.Name)
		require.Equal(t, []string{"https://e.example/2"}, got.Client.RedirectUris)
	})

	t.Run("StaleApply", func(t *testing.T) {
		c, _, err := ops.CreateClient(ctx, s, ops.ClientCreate{Name: "Stale", RedirectURIs: []string{"https://st.example/cb"}})
		require.NoError(t, err)
		id := c.Client.ClientID
		form := editForm(c)
		form.Set("name", "Stale Renamed")
		review := p.send("POST", clientURL("/client/review", id), form).Body.String()

		res, err := s.Q.GetOAuthResourceByURI(ctx, resA)
		require.NoError(t, err)
		require.NoError(t, s.Q.AddClientResource(ctx, db.AddClientResourceParams{ClientID: c.Client.ID, ResourceID: res.ID}))

		rec := p.send("POST", clientURL("/client/apply", id), hiddenFields(t, review, "/client/apply"))
		require.Equal(t, http.StatusConflict, rec.Code)
		require.Contains(t, rec.Body.String(), "changed since you reviewed it")
		got, err := ops.GetClient(ctx, s, id)
		require.NoError(t, err)
		require.Equal(t, "Stale", got.Client.Name)
	})

	t.Run("ValidationErrorShownOnForm", func(t *testing.T) {
		c, _, err := ops.CreateClient(ctx, s, ops.ClientCreate{Name: "Wild", RedirectURIs: []string{"https://*.preview.example.com/cb"}})
		require.NoError(t, err)
		form := editForm(c)
		form.Set("trusted", "on")
		review := p.send("POST", clientURL("/client/review", c.Client.ClientID), form).Body.String()
		rec := p.send("POST", clientURL("/client/apply", c.Client.ClientID), hiddenFields(t, review, "/client/apply"))
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		require.Contains(t, rec.Body.String(), "wildcard")
	})

	t.Run("CreateConfidentialShowsSecret", func(t *testing.T) {
		rec := p.send("POST", "/clients/new", url.Values{
			"name": {"Backend"}, "redirect_uris": {"https://be.example/cb"},
			"scopes": {"openid"}, "confidential": {"on"}, "resources": {resA},
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		page := rec.Body.String()
		require.Contains(t, page, "cannot be retrieved later")
		clients, err := ops.ListClients(ctx, s)
		require.NoError(t, err)
		var made db.OauthClient
		for _, c := range clients {
			if c.Name == "Backend" {
				made = c
			}
		}
		require.True(t, made.ClientSecret.Valid)
		require.Contains(t, page, made.ClientID)
		require.Contains(t, page, `data-copy="`+html.EscapeString(made.ClientID)+`"`)
		require.Equal(t, 2, strings.Count(page, "data-copy="), "client ID and secret are both copyable")
	})

	t.Run("CIMDReadOnly", func(t *testing.T) {
		const cimd = "https://claude.ai/oauth/claude-code-client-metadata"
		_, err := s.Q.CreateCIMDClient(ctx, db.CreateCIMDClientParams{ClientID: cimd, Name: "Claude",
			RedirectUris: []string{"https://claude.ai/api/mcp/auth_callback"}})
		require.NoError(t, err)
		page := p.get(clientURL("/client", cimd))
		require.Contains(t, page, "Claude")
		require.NotContains(t, page, `action="/client/review`)
		rec := p.send("POST", clientURL("/client/review", cimd), url.Values{"name": {"Sneaky"}})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("ProdDeleteNeedsName", func(t *testing.T) {
		prod := newPanel(t, s, "prod")
		c, _, err := ops.CreateClient(ctx, s, ops.ClientCreate{Name: "Doomed", RedirectURIs: []string{"https://d.example/cb"}})
		require.NoError(t, err)
		id := c.Client.ClientID
		page := prod.get(clientURL("/client/delete", id))
		require.Contains(t, page, "[PROD]")

		rec := prod.send("POST", clientURL("/client/delete", id), url.Values{"confirm_name": {"wrong"}})
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		_, err = ops.GetClient(ctx, s, id)
		require.NoError(t, err, "not deleted")

		rec = prod.send("POST", clientURL("/client/delete", id), url.Values{"confirm_name": {"Doomed"}})
		require.Equal(t, http.StatusSeeOther, rec.Code)
		_, err = ops.GetClient(ctx, s, id)
		require.Error(t, err, "deleted")
	})

	t.Run("ResourceEditFlow", func(t *testing.T) {
		rec := p.send("POST", "/resources/new", url.Values{
			"uri": {"https://new.example.com/api/"}, "name": {"New API"},
			"scope_name": {"n:read", ""}, "scope_desc": {"Read N", ""},
		})
		require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
		const uri = "https://new.example.com/api"
		r, err := ops.GetResource(ctx, s, uri)
		require.NoError(t, err)
		require.Equal(t, map[string]string{"n:read": "Read N"}, r.Scopes)

		page := p.get("/resource?uri=" + url.QueryEscape(uri))
		require.Contains(t, page, "New API")
		rec = p.send("POST", "/resource/review?uri="+url.QueryEscape(uri), url.Values{
			"name":        {"New API"},
			"scope_name":  {"n:write", "", ""},
			"scope_desc":  {"Write N", "", ""},
			"fingerprint": {r.Fingerprint()},
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		review := rec.Body.String()
		require.Contains(t, review, "n:read: Read N", "the removed scope is shown")
		require.Contains(t, review, "n:write: Write N")

		rec = p.send("POST", "/resource/apply?uri="+url.QueryEscape(uri), hiddenFields(t, review, "/resource/apply"))
		require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
		r, err = ops.GetResource(ctx, s, uri)
		require.NoError(t, err)
		require.Equal(t, map[string]string{"n:write": "Write N"}, r.Scopes)
	})

	t.Run("ResourceCreateRefusesIdentityScope", func(t *testing.T) {
		rec := p.send("POST", "/resources/new", url.Values{
			"uri": {"https://bad.example.com"}, "name": {"Bad"},
			"scope_name": {"openid"}, "scope_desc": {"Sign in"},
		})
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		require.Contains(t, rec.Body.String(), "identity&#39;s own scopes")
	})

	t.Run("ResourceDeleteInUse", func(t *testing.T) {
		_, _, err := ops.CreateClient(ctx, s, ops.ClientCreate{Name: "Uses A", RedirectURIs: []string{"https://ua.example/cb"}, DefaultResource: resA})
		require.NoError(t, err)
		rec := p.send("POST", "/resource/delete?uri="+url.QueryEscape(resA), url.Values{})
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		require.Contains(t, rec.Body.String(), "Uses A")
		_, err = ops.GetResource(ctx, s, resA)
		require.NoError(t, err, "still there")
	})
}
