//go:build integration

package httpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/cimd"
	"github.com/eswan18/identity/pkg/db"
)

// Clients identified by a Client ID Metadata Document, end to end (spec
// docs/superpowers/specs/2026-10-27-resource-indicators-and-mcp-clients-design.md,
// sections 8 and 9). The suite's resolver is a fake allowing claude.ai
// (SetupSuite); tests serve documents through s.cimd.

const loopbackWarning = "This app runs on your computer"

// randomCIMDClientID is a fresh claude.ai client_id, so tests sharing the
// suite's database never share a materialized client.
func (s *OAuthFlowSuite) randomCIMDClientID() string {
	return "https://claude.ai/oauth/test-" + strings.ToLower(s.mustGenerateAlphanumericString(10)) + "/client-metadata"
}

// mustRegisterDynamicResource registers a resource metadata-document clients
// may request (dynamic_clients = true).
func (s *OAuthFlowSuite) mustRegisterDynamicResource(uri, name string, scopes map[string]string) db.OauthResource {
	s.T().Helper()
	raw, err := json.Marshal(scopes)
	s.Require().NoError(err)
	resource, err := s.datastore.Q.CreateOAuthResource(s.T().Context(), db.CreateOAuthResourceParams{
		Uri: uri, Name: name, Scopes: raw, DynamicClients: true,
	})
	s.Require().NoError(err)
	return resource
}

func (s *OAuthFlowSuite) mustRegisterSensibilityLikeResource() db.OauthResource {
	return s.mustRegisterDynamicResource(s.randomResourceURI(), "Sensibility Test", map[string]string{
		"sensibility:read":  "Read your accounts and balances",
		"sensibility:write": "Change your accounts and balances",
	})
}

// mustSignIn signs a fresh user in and returns their browser.
func (s *OAuthFlowSuite) mustSignIn() *http.Client {
	s.T().Helper()
	username := s.mustGenerateAlphanumericString(10)
	password := s.mustGenerateRandomString(16)
	s.mustRegisterUser(username, password, username+"@example.com")
	jar, err := cookiejar.New(nil)
	s.Require().NoError(err)
	browser := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/login", url.Values{
		"username": {username}, "password": {password},
	})
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	return browser
}

// cimdAuthorizeQuery is an authorize request from a metadata-document client.
func cimdAuthorizeQuery(clientID, redirectURI, scope string, scv StateAndCodeVerifier, resource string) string {
	var extra url.Values
	if resource != "" {
		extra = url.Values{"resource": {resource}}
	}
	return authorizeQueryFor(clientID, redirectURI, scope, scv, extra)
}

// requireRedirectTo asserts resp redirects to redirectURI (and nowhere else)
// and returns the query it carries.
func (s *OAuthFlowSuite) requireRedirectTo(resp *http.Response, redirectURI string) url.Values {
	s.T().Helper()
	defer resp.Body.Close()
	s.Require().Equal(http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	s.Require().NoError(err)
	s.Require().Equal(redirectURI, location.Scheme+"://"+location.Host+location.Path,
		"expected a redirect to the client, got %s", resp.Header.Get("Location"))
	return location.Query()
}

// requireErrorPage asserts resp is an error page: a 400 with no redirect.
func (s *OAuthFlowSuite) requireErrorPage(resp *http.Response) {
	s.T().Helper()
	defer resp.Body.Close()
	s.Equal(http.StatusBadRequest, resp.StatusCode)
	s.Empty(resp.Header.Get("Location"), "an unverified redirect_uri must never be redirected to")
}

// cimdExchange redeems code as a public metadata-document client: client_id
// alone, PKCE, no secret.
func (s *OAuthFlowSuite) cimdExchange(clientID, redirectURI, code string, scv StateAndCodeVerifier, extra url.Values) (int, map[string]any) {
	s.T().Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {scv.CodeVerifier},
	}
	for k, v := range extra {
		form[k] = v
	}
	return s.postTokenForm(form)
}

func (s *OAuthFlowSuite) cimdClientRow(clientID string) db.OauthClient {
	s.T().Helper()
	row, err := s.datastore.Q.GetOAuthClientByClientID(s.T().Context(), clientID)
	s.Require().NoError(err)
	return row
}

func (s *OAuthFlowSuite) consentCount(clientID string) int {
	s.T().Helper()
	var n int
	s.Require().NoError(s.datastore.DB.QueryRowContext(s.T().Context(),
		`SELECT count(*) FROM oauth_user_consents uc JOIN oauth_clients c ON c.id = uc.client_id WHERE c.client_id = $1`,
		clientID).Scan(&n))
	return n
}

// TestCIMDClaudeCodeFlow is Claude Code connecting to an MCP server: its
// client_id is the URL of its metadata document, which registers port-less
// loopback redirect URIs, and it calls back on an ephemeral port. Nothing is
// registered by hand. The consent screen names claude.ai as the app, with the
// document's own name only as a claim, and warns that the app runs locally;
// the token is for the resource, and refreshes.
func (s *OAuthFlowSuite) TestCIMDClaudeCodeFlow() {
	const clientID = claudeCodeClientID
	s.cimd.serve(clientID, "Claude Code", "http://localhost/callback", "http://127.0.0.1/callback")
	resource := s.mustRegisterSensibilityLikeResource()
	browser := s.mustSignIn()
	scv := s.mustCreateStateAndCodeVerifier()
	const redirectURI = "http://localhost:53682/callback"
	const scope = "sensibility:read sensibility:write offline_access"

	query := cimdAuthorizeQuery(clientID, redirectURI, scope, scv, resource.Uri)
	consentURL := s.requireConsentRedirect(s.get(browser, testBaseURL+"/oauth/authorize?"+query))

	page := s.mustConsentPage(browser, consentURL)
	s.Contains(page, "<strong>claude.ai</strong> is requesting", "the client_id's host is the app")
	s.Contains(page, "It calls itself “Claude Code”", "the document's name is shown only as a claim")
	s.Contains(page, loopbackWarning)
	s.Contains(page, "<strong>localhost:53682</strong>", "where the answer goes, port included")
	s.Contains(page, "Sensibility Test")
	s.Contains(page, "Read your accounts and balances")

	// The client was materialized on first use.
	row := s.cimdClientRow(clientID)
	s.Equal(clientKindCIMD, row.Kind)
	s.Equal("Claude Code", row.Name)
	s.Equal([]string{"http://localhost/callback", "http://127.0.0.1/callback"}, row.RedirectUris)
	s.False(row.IsConfidential)
	s.False(row.ClientSecret.Valid)
	s.False(row.DefaultResource.Valid)
	s.True(row.MetadataFetchedAt.Valid)

	code := s.mustApprove(browser, consentURL)
	status, body := s.cimdExchange(clientID, redirectURI, code, scv, nil)
	s.Require().Equal(http.StatusOK, status, "%v", body)
	s.Equal(`["`+resource.Uri+`"]`, s.accessTokenRawAud(body["access_token"].(string)))
	s.Equal(scope, body["scope"])

	refreshed := s.mustRefreshAt(testBaseURL, clientID, body["refresh_token"].(string))
	s.Equal(`["`+resource.Uri+`"]`, s.accessTokenRawAud(refreshed.AccessToken))

	// Consent is remembered for (user, client, resource): the next sign-in,
	// on another ephemeral port, goes straight back with a code.
	scv = s.mustCreateStateAndCodeVerifier()
	again := s.get(browser, testBaseURL+"/oauth/authorize?"+cimdAuthorizeQuery(clientID, "http://127.0.0.1:61000/callback", scope, scv, resource.Uri))
	s.NotEmpty(s.requireRedirectTo(again, "http://127.0.0.1:61000/callback").Get("code"))

	// But not for another resource.
	other := s.mustRegisterSensibilityLikeResource()
	s.requireConsentRedirect(s.get(browser, testBaseURL+"/oauth/authorize?"+cimdAuthorizeQuery(clientID, redirectURI, scope, scv, other.Uri)))
}

// TestCIMDClaudeAIFlow is claude.ai's shape: a web redirect URI on claude.ai
// itself, so no loopback warning.
func (s *OAuthFlowSuite) TestCIMDClaudeAIFlow() {
	clientID := s.randomCIMDClientID()
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	s.cimd.serve(clientID, "Claude", redirectURI)
	resource := s.mustRegisterSensibilityLikeResource()
	browser := s.mustSignIn()
	scv := s.mustCreateStateAndCodeVerifier()

	query := cimdAuthorizeQuery(clientID, redirectURI, "sensibility:read offline_access", scv, resource.Uri)
	consentURL := s.requireConsentRedirect(s.get(browser, testBaseURL+"/oauth/authorize?"+query))
	page := s.mustConsentPage(browser, consentURL)
	s.Contains(page, "<strong>claude.ai</strong> is requesting")
	s.Contains(page, "It calls itself “Claude”")
	s.NotContains(page, loopbackWarning)

	u, err := url.Parse(consentURL)
	s.Require().NoError(err)
	resp, err := csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/consent", url.Values{
		"decision": {"allow"}, "authorize_query": {u.Query().Get("authorize_query")},
	})
	s.Require().NoError(err)
	back := s.requireRedirectTo(resp, redirectURI)
	s.Equal(scv.State, back.Get("state"))
	s.Equal(testBaseURL, back.Get("iss"))

	status, body := s.cimdExchange(clientID, redirectURI, back.Get("code"), scv, url.Values{"resource": {resource.Uri}})
	s.Require().Equal(http.StatusOK, status, "%v", body)
	s.Equal(`["`+resource.Uri+`"]`, s.accessTokenRawAud(body["access_token"].(string)))
}

// TestCIMDHostNotAllowed: a client_id on a host off the allow-list is an
// unknown client everywhere, and nothing is fetched for it.
func (s *OAuthFlowSuite) TestCIMDHostNotAllowed() {
	const clientID = "https://mcp-client.example.com/oauth/client-metadata"
	const redirectURI = "https://mcp-client.example.com/callback"
	s.cimd.serve(clientID, "Not Allowed", redirectURI)
	browser := s.mustSignIn()
	scv := s.mustCreateStateAndCodeVerifier()

	s.requireErrorPage(s.get(browser, testBaseURL+"/oauth/authorize?"+cimdAuthorizeQuery(clientID, redirectURI, "openid", scv, "")))
	status, body := s.postTokenForm(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {clientID}})
	s.Equal(http.StatusUnauthorized, status)
	s.Equal("invalid_client", body["error"])

	s.Equal(0, s.cimd.fetchCount(clientID), "nothing is fetched before the allow-list check")
	_, err := s.datastore.Q.GetOAuthClientByClientID(s.T().Context(), clientID)
	s.Error(err, "no client was materialized")
}

// TestCIMDResolveErrors: a document that cannot be fetched, or is invalid,
// makes its client unknown: an error page (never a redirect) at authorize and
// consent, invalid_client at the token endpoint -- even for a client that was
// materialized and granted tokens before.
func (s *OAuthFlowSuite) TestCIMDResolveErrors() {
	clientID := s.randomCIMDClientID()
	const redirectURI = "http://localhost/callback"
	s.cimd.serve(clientID, "Claude Code", redirectURI)
	resource := s.mustRegisterSensibilityLikeResource()
	browser := s.mustSignIn()
	scv := s.mustCreateStateAndCodeVerifier()
	query := cimdAuthorizeQuery(clientID, redirectURI, "sensibility:read", scv, resource.Uri)
	code := s.mustCodeFor(browser, query)
	status, body := s.cimdExchange(clientID, redirectURI, code, scv, nil)
	s.Require().Equal(http.StatusOK, status, "%v", body)
	refresh := body["refresh_token"].(string)

	for name, resolveErr := range map[string]error{
		"fetch error":      fmt.Errorf("%w: status 403", cimd.ErrFetch),
		"invalid document": fmt.Errorf("%w: client_id does not match", cimd.ErrInvalidDocument),
	} {
		s.Run(name, func() {
			s.cimd.fail(clientID, resolveErr)
			s.requireErrorPage(s.get(browser, testBaseURL+"/oauth/authorize?"+query))
			consentURL := testBaseURL + "/oauth/consent?" + url.Values{"authorize_query": {query}}.Encode()
			s.requireErrorPage(s.get(browser, consentURL))
			resp, err := csrfPostFormLogin(s.T(), browser, testBaseURL+"/oauth/consent", url.Values{
				"decision": {"allow"}, "authorize_query": {query},
			})
			s.Require().NoError(err)
			s.requireErrorPage(resp)

			status, body := s.postTokenForm(url.Values{
				"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID},
			})
			s.Equal(http.StatusUnauthorized, status)
			s.Equal("invalid_client", body["error"])
		})
	}

	// Once the document is back, so is the client, and the refused refreshes
	// did not spend the token.
	s.cimd.serve(clientID, "Claude Code", redirectURI)
	refreshed := s.mustRefreshAt(testBaseURL, clientID, refresh)
	s.NotEmpty(refreshed.AccessToken)
}

// TestCIMDResourceNotForDynamicClients: a metadata-document client may only
// request resources with dynamic_clients = true. Its redirect URI is verified,
// so the refusal goes back to it.
func (s *OAuthFlowSuite) TestCIMDResourceNotForDynamicClients() {
	clientID := s.randomCIMDClientID()
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	s.cimd.serve(clientID, "Claude", redirectURI)
	closed := s.mustRegisterResource(s.randomResourceURI(), "Registered Clients Only", map[string]string{"x:read": "Read X"})
	browser := s.mustSignIn()
	scv := s.mustCreateStateAndCodeVerifier()

	for _, b := range []*http.Client{browser, s.httpClient} {
		resp := s.get(b, testBaseURL+"/oauth/authorize?"+cimdAuthorizeQuery(clientID, redirectURI, "x:read", scv, closed.Uri))
		s.Equal("invalid_target", s.requireRedirectTo(resp, redirectURI).Get("error"))
	}
}

// TestCIMDScopes: a metadata-document client may ask for identity's user
// scopes and the requested resource's, nothing else; with no resource,
// identity's alone.
func (s *OAuthFlowSuite) TestCIMDScopes() {
	clientID := s.randomCIMDClientID()
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	s.cimd.serve(clientID, "Claude", redirectURI)
	resource := s.mustRegisterSensibilityLikeResource()
	browser := s.mustSignIn()
	scv := s.mustCreateStateAndCodeVerifier()

	refused := map[string]string{
		"resource scope without a resource":  cimdAuthorizeQuery(clientID, redirectURI, "openid sensibility:read", scv, ""),
		"scope the resource does not define": cimdAuthorizeQuery(clientID, redirectURI, "sensibility:read other:read", scv, resource.Uri),
		"admin scope":                        cimdAuthorizeQuery(clientID, redirectURI, "admin:users:read", scv, ""),
	}
	for name, query := range refused {
		s.Run(name, func() {
			resp := s.get(browser, testBaseURL+"/oauth/authorize?"+query)
			s.Equal("invalid_scope", s.requireRedirectTo(resp, redirectURI).Get("error"))
		})
	}

	// Identity's scopes with no resource: a token for identity itself.
	code := s.mustCodeFor(browser, cimdAuthorizeQuery(clientID, redirectURI, "openid profile email offline_access", scv, ""))
	status, body := s.cimdExchange(clientID, redirectURI, code, scv, nil)
	s.Require().Equal(http.StatusOK, status, "%v", body)
	s.Equal(`["`+testBaseURL+`"]`, s.accessTokenRawAud(body["access_token"].(string)))
}

// TestCIMDTokenEndpointRules: a metadata-document client authenticates with
// "none" -- a secret is refused, not ignored -- and may not use
// client_credentials.
func (s *OAuthFlowSuite) TestCIMDTokenEndpointRules() {
	clientID := s.randomCIMDClientID()
	s.cimd.serve(clientID, "Claude", "https://claude.ai/api/mcp/auth_callback")

	status, body := s.postTokenForm(url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}})
	s.Equal(http.StatusBadRequest, status)
	s.Equal("unauthorized_client", body["error"])

	status, body = s.postTokenForm(url.Values{
		"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {"anything"},
	})
	s.Equal(http.StatusUnauthorized, status)
	s.Equal("invalid_client", body["error"])
}

// TestCIMDRefetchChangedRedirectURIsClearsConsent: when a re-fetched document
// lists different redirect URIs, the row follows it and every remembered
// consent for the client is forgotten (CIMD §8.4) -- users approved sending
// answers to the old ones. A re-fetch that changes nothing keeps them, and a
// redirect URI the document no longer lists stops working.
func (s *OAuthFlowSuite) TestCIMDRefetchChangedRedirectURIsClearsConsent() {
	clientID := s.randomCIMDClientID()
	resource := s.mustRegisterSensibilityLikeResource()
	browser := s.mustSignIn()
	scv := s.mustCreateStateAndCodeVerifier()
	const oldRedirect, newRedirect = "https://claude.ai/api/mcp/auth_callback", "https://claude.ai/api/mcp/v2/auth_callback"
	authorize := func(redirectURI string) *http.Response {
		return s.get(browser, testBaseURL+"/oauth/authorize?"+cimdAuthorizeQuery(clientID, redirectURI, "sensibility:read", scv, resource.Uri))
	}

	s.cimd.serve(clientID, "Claude", oldRedirect)
	s.mustCodeFor(browser, cimdAuthorizeQuery(clientID, oldRedirect, "sensibility:read", scv, resource.Uri))
	s.Equal(1, s.consentCount(clientID))
	firstFetch := s.cimdClientRow(clientID).MetadataFetchedAt.Time

	// Unchanged document, fetched again: the fetch is recorded, the consent kept.
	time.Sleep(2 * time.Millisecond)
	s.cimd.serve(clientID, "Claude", oldRedirect)
	s.NotEmpty(s.requireRedirectTo(authorize(oldRedirect), oldRedirect).Get("code"), "consent is still remembered")
	s.Equal(1, s.consentCount(clientID))
	s.True(s.cimdClientRow(clientID).MetadataFetchedAt.Time.After(firstFetch))

	// A new name alone keeps the consent too.
	time.Sleep(2 * time.Millisecond)
	s.cimd.serve(clientID, "Claude (renamed)", oldRedirect)
	s.NotEmpty(s.requireRedirectTo(authorize(oldRedirect), oldRedirect).Get("code"))
	s.Equal("Claude (renamed)", s.cimdClientRow(clientID).Name)
	s.Equal(1, s.consentCount(clientID))

	// Tokens issued under the old redirect URIs, and a code not yet exchanged.
	code := s.requireRedirectTo(authorize(oldRedirect), oldRedirect).Get("code")
	status, tokens := s.cimdExchange(clientID, oldRedirect, code, scv, nil)
	s.Require().Equal(http.StatusOK, status, "%v", tokens)
	pending := s.requireRedirectTo(authorize(oldRedirect), oldRedirect).Get("code")

	// Changed redirect URIs: consent is forgotten, the old URI is refused,
	// and every grant made under the old ones is withdrawn with it: the
	// tokens are revoked (a refresh is refused) and the code is gone.
	time.Sleep(2 * time.Millisecond)
	s.cimd.serve(clientID, "Claude", newRedirect)
	s.requireConsentRedirect(authorize(newRedirect))
	s.Equal(0, s.consentCount(clientID))
	s.Equal([]string{newRedirect}, s.cimdClientRow(clientID).RedirectUris)
	s.requireErrorPage(authorize(oldRedirect))

	row := s.tokenRow(tokens["refresh_token"].(string))
	s.True(row.RevokedAt.Valid, "tokens issued under the old redirect URIs are revoked")
	s.Equal("client_redirects_changed", row.RevokedReason.String)
	s.requireInvalidGrant(s.cimdClientRow(clientID), tokens["refresh_token"].(string), "no refresh after the redirect URIs changed")
	status, body := s.cimdExchange(clientID, oldRedirect, pending, scv, nil)
	s.Equal(http.StatusBadRequest, status)
	s.Equal("invalid_grant", body["error"], "an unexchanged code is gone")
}

// TestCIMDOlderFetchNeverOverwritesNewer: each pod caches documents on its
// own, so one can resolve an older copy than the row holds. The row keeps the
// newer one.
func (s *OAuthFlowSuite) TestCIMDOlderFetchNeverOverwritesNewer() {
	clientID := s.randomCIMDClientID()
	now := time.Now().Truncate(time.Microsecond)
	newer := &cimd.Metadata{ClientID: clientID, ClientName: "Newer", RedirectURIs: []string{"https://claude.ai/new"}, FetchedAt: now}
	older := &cimd.Metadata{ClientID: clientID, ClientName: "Older", RedirectURIs: []string{"https://claude.ai/old"}, FetchedAt: now.Add(-time.Minute)}

	_, err := s.server.materializeCIMDClient(s.T().Context(), newer)
	s.Require().NoError(err)
	got, err := s.server.materializeCIMDClient(s.T().Context(), older)
	s.Require().NoError(err)
	s.Equal("Newer", got.Name)
	s.Equal([]string{"https://claude.ai/new"}, s.cimdClientRow(clientID).RedirectUris)
}

// TestCIMDRegisteredClientAtURLIsRefused: a hand-registered row whose
// client_id happens to be a metadata-document URL is neither overwritten by
// the document nor used in its place.
func (s *OAuthFlowSuite) TestCIMDRegisteredClientAtURLIsRefused() {
	clientID := s.randomCIMDClientID()
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID: clientID, Name: "Hand Registered", RedirectUris: []string{redirectURI}, AllowedScopes: []string{"openid"},
	})
	s.cimd.serve(clientID, "Claude", redirectURI)
	browser := s.mustSignIn()
	scv := s.mustCreateStateAndCodeVerifier()

	s.requireErrorPage(s.get(browser, testBaseURL+"/oauth/authorize?"+cimdAuthorizeQuery(clientID, redirectURI, "openid", scv, "")))
	row := s.cimdClientRow(clientID)
	s.Equal("registered", row.Kind)
	s.Equal("Hand Registered", row.Name)
}

// TestCIMDLogoutHonoursDocumentRedirects: logout's post_logout_redirect_uri is
// matched against the redirect URIs the client's document last listed.
func (s *OAuthFlowSuite) TestCIMDLogoutHonoursDocumentRedirects() {
	clientID := s.randomCIMDClientID()
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	s.cimd.serve(clientID, "Claude", redirectURI)
	browser := s.mustSignIn()
	scv := s.mustCreateStateAndCodeVerifier()
	// Materialize the client.
	s.requireConsentRedirect(s.get(browser, testBaseURL+"/oauth/authorize?"+cimdAuthorizeQuery(clientID, redirectURI, "openid", scv, "")))

	resp := s.get(browser, testBaseURL+"/oauth/logout?"+url.Values{
		"client_id": {clientID}, "post_logout_redirect_uri": {redirectURI},
	}.Encode())
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	s.Equal(http.StatusFound, resp.StatusCode)
	s.Equal(redirectURI, resp.Header.Get("Location"))
}

// Parser tests use the captured ChatGPT document. This layer uses the suite's
// resolver seam to test the resulting public client's full consent/PKCE flow.
func (s *OAuthFlowSuite) TestCIMDChatGPTFlow() {
	const clientID = "https://chatgpt.com/oauth/client.json"
	const redirectURI = "https://chatgpt.com/connector_platform_oauth_redirect"
	s.cimd.serve(clientID, "ChatGPT", redirectURI)
	resource := s.mustRegisterDynamicResource(s.randomResourceURI(), "Footstrike Test", map[string]string{"footstrike:read": "Read your runs, training load and shoes"})
	browser := s.mustSignIn()
	scv := s.mustCreateStateAndCodeVerifier()
	query := cimdAuthorizeQuery(clientID, redirectURI, "openid profile email offline_access footstrike:read", scv, resource.Uri)
	consentURL := s.requireConsentRedirect(s.get(browser, testBaseURL+"/oauth/authorize?"+query))
	page := s.mustConsentPage(browser, consentURL)
	s.Contains(page, "<strong>chatgpt.com</strong> is requesting")
	s.Contains(page, "Footstrike Test")
	s.Contains(page, "Read your runs, training load and shoes")
	s.NotContains(page, loopbackWarning)
	row := s.cimdClientRow(clientID)
	s.False(row.Trusted)
	s.False(row.IsConfidential)
	s.False(row.ClientSecret.Valid)
	s.False(row.DefaultResource.Valid)
	code := s.mustApprove(browser, consentURL)
	// No shared secret is accepted, despite the legacy private_key_jwt preference.
	status, body := s.cimdExchange(clientID, redirectURI, code, scv, url.Values{"client_secret": {"not-a-secret"}})
	s.Equal(http.StatusUnauthorized, status)
	s.Equal("invalid_client", body["error"])
	status, body = s.cimdExchange(clientID, redirectURI, code, scv, url.Values{"resource": {resource.Uri}})
	s.Require().Equal(http.StatusOK, status, "%v", body)
	s.Equal(`["`+resource.Uri+`"]`, s.accessTokenRawAud(body["access_token"].(string)))
	s.NotEmpty(body["id_token"])
	refreshed := s.mustRefreshAt(testBaseURL, clientID, body["refresh_token"].(string))
	s.Equal(`["`+resource.Uri+`"]`, s.accessTokenRawAud(refreshed.AccessToken))
	// A forged redirect remains invalid even for the newly allowed host.
	s.requireErrorPage(s.get(browser, testBaseURL+"/oauth/authorize?"+cimdAuthorizeQuery(clientID, "https://chatgpt.com/other", "footstrike:read", scv, resource.Uri)))
}
