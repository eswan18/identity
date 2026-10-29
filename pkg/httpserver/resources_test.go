//go:build integration

package httpserver

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/config"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/email"
	"github.com/eswan18/identity/pkg/storage"
	"github.com/eswan18/identity/pkg/store"
	"github.com/golang-migrate/migrate/v4"
	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// Tests for the resources registry and the access-token format (spec
// docs/superpowers/specs/2026-10-27-resource-indicators-and-mcp-clients-design.md,
// sections 1, 2, 4 and 11).

// jwtSegmentJSON returns one segment of a compact JWT as raw JSON fields, so the
// assertions see the exact bytes a resource server would, not what a Go claims
// type makes of them.
func (s *OAuthFlowSuite) jwtSegmentJSON(token string, index int) map[string]json.RawMessage {
	s.T().Helper()
	parts := strings.Split(token, ".")
	s.Require().Len(parts, 3, "expected a compact JWT")
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	s.Require().NoError(err)
	var fields map[string]json.RawMessage
	s.Require().NoError(json.Unmarshal(raw, &fields))
	return fields
}

// accessTokenRawAud returns an access token's aud exactly as serialized.
func (s *OAuthFlowSuite) accessTokenRawAud(token string) string {
	s.T().Helper()
	return string(s.jwtSegmentJSON(token, 1)["aud"])
}

// mustPostTokenAt posts a token request to baseURL and decodes a 200 response.
func (s *OAuthFlowSuite) mustPostTokenAt(baseURL string, form url.Values) TokenResponse {
	s.T().Helper()
	resp, err := s.httpClient.PostForm(baseURL+"/oauth/token", form)
	s.Require().NoError(err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, resp.StatusCode, "token request failed: %s", body)
	var tokens TokenResponse
	s.Require().NoError(json.Unmarshal(body, &tokens))
	return tokens
}

func (s *OAuthFlowSuite) mustRefreshAt(baseURL, clientID, refreshToken string) TokenResponse {
	s.T().Helper()
	return s.mustPostTokenAt(baseURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
}

// tokenRowResource reads the resource recorded on the token row for a refresh token.
func (s *OAuthFlowSuite) tokenRowResource(datastore *store.Store, refreshToken string) sql.NullString {
	s.T().Helper()
	var resource sql.NullString
	s.Require().NoError(datastore.DB.QueryRowContext(s.T().Context(),
		`SELECT resource FROM oauth_tokens WHERE refresh_token = $1`, refreshToken).Scan(&resource))
	return resource
}

// TestLegacyAudienceSurvivesMigration is the compatibility guarantee for every
// existing client, footstrike-api's above all: a client registered with
// audience X before migration 000012 still gets aud == ["X"], byte for byte,
// after it -- through a code exchange and through refreshes, including refresh
// tokens minted before the migration and ones the previous release mints after
// it, while it is still serving -- and all of that still holds once 000014 has
// contracted the schema (audience and the trigger gone).
//
// It runs against its own database, migrated to 11, given a client the way the
// old schema held one, and only then migrated forward; the suite's shared
// database was created at the latest version and has no such client.
func (s *OAuthFlowSuite) TestLegacyAudienceSurvivesMigration() {
	ctx := s.T().Context()
	const legacyAudience = "ethanswan:fitness" // URN-style; must not be canonicalized

	pg, err := postgres.Run(ctx, fmt.Sprintf("postgres:%s", testPgVersion),
		postgres.WithDatabase(testPgDatabase),
		postgres.WithUsername(testPgUser),
		postgres.WithPassword(testPgPassword),
		postgres.BasicWaitStrategies(),
		postgres.WithSQLDriver("pgx"),
	)
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = pg.Terminate(ctx) })
	dbURL, err := pg.ConnectionString(ctx, "sslmode=disable")
	s.Require().NoError(err)
	migrationsDir, err := filepath.Abs("../../db/migrations")
	s.Require().NoError(err)
	m, err := migrate.New("file://"+migrationsDir, dbURL)
	s.Require().NoError(err)
	s.T().Cleanup(func() { m.Close() })
	s.Require().NoError(m.Migrate(11))

	ds, err := store.New(dbURL)
	s.Require().NoError(err)
	s.T().Cleanup(func() { ds.DB.Close() })

	// The world before 000012, written in its own terms.
	clientID := s.mustGenerateRandomString(8)
	redirectURI := "http://localhost:8080/callback"
	var clientUUID, userUUID string
	s.Require().NoError(ds.DB.QueryRowContext(ctx, `
		INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes, is_confidential, audience)
		VALUES ($1, 'Footstrike Dashboard', $2, '{openid,profile,email}', false, $3)
		RETURNING id`, clientID, []string{redirectURI}, legacyAudience).Scan(&clientUUID))
	s.Require().NoError(ds.DB.QueryRowContext(ctx, `
		INSERT INTO auth_users (username, password_hash, email)
		VALUES ($1, 'not-a-real-hash', $2)
		RETURNING id`, s.mustGenerateAlphanumericString(10), s.mustGenerateAlphanumericString(10)+"@example.com").Scan(&userUUID))
	preMigrationRefresh := s.mustGenerateRandomString(32)
	_, err = ds.DB.ExecContext(ctx, `
		INSERT INTO oauth_tokens (access_token, refresh_token, user_id, client_id, scope, expires_at, refresh_expires_at)
		VALUES ($1, $2, $3, $4, '{openid,profile,email}', now() + interval '1 hour', now() + interval '30 days')`,
		s.mustGenerateRandomString(16), preMigrationRefresh, userUUID, clientUUID)
	s.Require().NoError(err)

	// Expand (000012, 000013) only: the previous release keeps serving until the
	// new one rolls out, and its token INSERT names no resource column.
	s.Require().NoError(m.Migrate(13))
	oldReleaseRefresh := s.mustGenerateRandomString(32)
	_, err = ds.DB.ExecContext(ctx, `
		INSERT INTO oauth_tokens (access_token, refresh_token, user_id, client_id, scope, expires_at, refresh_expires_at)
		VALUES ($1, $2, $3, $4, '{openid,profile,email}', now() + interval '1 hour', now() + interval '30 days')`,
		s.mustGenerateRandomString(16), oldReleaseRefresh, userUUID, clientUUID)
	s.Require().NoError(err)

	// The rollout is done; contract.
	s.Require().NoError(m.Up())

	// The backfill: one resource, named after the client, URI byte for byte.
	resource, err := ds.Q.GetOAuthResourceByURI(ctx, legacyAudience)
	s.Require().NoError(err)
	s.Equal("Footstrike Dashboard", resource.Name)
	s.False(resource.DynamicClients)
	client, err := ds.Q.GetOAuthClientByClientID(ctx, clientID)
	s.Require().NoError(err)
	s.Equal(sql.NullString{String: legacyAudience, Valid: true}, client.DefaultResource)
	s.Equal("registered", client.Kind)

	// Serve the migrated database with this build.
	srv := New(&config.Config{JWTPrivateKey: testJWTPrivateKey, JWTIssuer: "http://localhost:8080"},
		ds, email.NewLogSender(), storage.NewLogStorage())
	ts := httptest.NewServer(srv.router)
	s.T().Cleanup(func() { ts.Close(); srv.Close() })

	wantAud := `["` + legacyAudience + `"]`

	// Code exchange. The code is planted directly: what is under test is the
	// token the client gets, not the login and consent pages.
	scv := s.mustCreateStateAndCodeVerifier()
	code := s.mustGenerateRandomString(32)
	s.Require().NoError(ds.Q.InsertAuthorizationCode(ctx, db.InsertAuthorizationCodeParams{
		Code:                code,
		UserID:              uuid.MustParse(userUUID),
		ClientID:            client.ID,
		RedirectUri:         redirectURI,
		Scope:               []string{"openid", "profile", "email"},
		CodeChallenge:       sql.NullString{String: scv.CodeChallenge, Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}))
	// And the consent it was issued under (000015 records it under the
	// client's default resource): the code exchange stores tokens only while
	// the user's consent is still there.
	s.Require().NoError(ds.Q.UpsertUserConsent(ctx, db.UpsertUserConsentParams{
		UserID:   uuid.MustParse(userUUID),
		ClientID: client.ID,
		Resource: client.DefaultResource,
		Scopes:   []string{"openid", "profile", "email"},
	}))

	exchanged := s.mustPostTokenAt(ts.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {scv.CodeVerifier},
	})
	s.Equal(wantAud, s.accessTokenRawAud(exchanged.AccessToken), "code exchange must keep the pre-migration aud")

	refreshed := s.mustRefreshAt(ts.URL, clientID, exchanged.RefreshToken)
	s.Equal(wantAud, s.accessTokenRawAud(refreshed.AccessToken), "refresh must keep the pre-migration aud")

	fromBeforeMigration := s.mustRefreshAt(ts.URL, clientID, preMigrationRefresh)
	s.Equal(wantAud, s.accessTokenRawAud(fromBeforeMigration.AccessToken),
		"a refresh token minted before the migration must keep its aud (backfilled resource)")

	fromOldRelease := s.mustRefreshAt(ts.URL, clientID, oldReleaseRefresh)
	s.Equal(wantAud, s.accessTokenRawAud(fromOldRelease.AccessToken),
		"a refresh token the previous release minted after the migration must keep its aud (trigger)")
}

// TestNoDefaultResourceAudienceIsIssuer: a client with no default resource
// gets tokens for identity itself, aud = [issuer], and the token row records
// the issuer explicitly, never NULL (see storedResource). So when the client
// later gains a default resource, refreshing the token it already has still
// yields aud = [issuer]: the grant is not re-pointed at the new resource.
func (s *OAuthFlowSuite) TestNoDefaultResourceAudienceIsIssuer() {
	const issuer = "http://localhost:8080"
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:       s.mustGenerateRandomString(8),
		Name:           s.mustGenerateRandomString(8),
		RedirectUris:   []string{"http://localhost:8080/callback"},
		AllowedScopes:  []string{"openid", "profile", "email"},
		IsConfidential: false,
	})
	s.Equal(`["`+issuer+`"]`, s.accessTokenRawAud(result.TokenResponse.AccessToken))
	s.Equal(testResource(issuer), s.tokenRowResource(s.datastore, result.TokenResponse.RefreshToken),
		"a token for identity itself stores the issuer, not NULL")

	refreshed := s.mustRefreshAt(issuer, result.Client.ClientID, result.TokenResponse.RefreshToken)
	s.Equal(`["`+issuer+`"]`, s.accessTokenRawAud(refreshed.AccessToken))
	s.Equal(testResource(issuer), s.tokenRowResource(s.datastore, refreshed.RefreshToken))

	// The client gains a default resource.
	mustEnsureDefaultResource(s.T(), s.datastore, db.CreateOAuthClientParams{DefaultResource: testResource("https://gained.example.com")})
	_, err := s.datastore.Q.UpdateOAuthClient(s.T().Context(), db.UpdateOAuthClientParams{
		ClientID:           result.Client.ClientID,
		SetDefaultResource: true,
		DefaultResource:    testResource("https://gained.example.com"),
	})
	s.Require().NoError(err)

	again := s.mustRefreshAt(issuer, result.Client.ClientID, refreshed.RefreshToken)
	s.Equal(`["`+issuer+`"]`, s.accessTokenRawAud(again.AccessToken),
		"refreshing an identity-audience token must not pick up the client's new default")
	s.Equal(testResource(issuer), s.tokenRowResource(s.datastore, again.RefreshToken))
	once := s.mustRefreshAt(issuer, result.Client.ClientID, again.RefreshToken)
	s.Equal(`["`+issuer+`"]`, s.accessTokenRawAud(once.AccessToken), "nor on any later refresh")
}

// TestRefreshKeepsStoredResourceAfterDefaultChanges: changing a client's
// default resource re-points new grants, never tokens already granted. Refresh
// used to re-read the client and so silently moved existing grants.
func (s *OAuthFlowSuite) TestRefreshKeepsStoredResourceAfterDefaultChanges() {
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:        s.mustGenerateRandomString(8),
		Name:            s.mustGenerateRandomString(8),
		RedirectUris:    []string{"http://localhost:8080/callback"},
		AllowedScopes:   []string{"openid", "profile", "email"},
		IsConfidential:  false,
		DefaultResource: testResource("https://original.example.com"),
	})
	s.Equal(`["https://original.example.com"]`, s.accessTokenRawAud(result.TokenResponse.AccessToken))
	s.Equal(testResource("https://original.example.com"), s.tokenRowResource(s.datastore, result.TokenResponse.RefreshToken))

	mustEnsureDefaultResource(s.T(), s.datastore, db.CreateOAuthClientParams{DefaultResource: testResource("https://changed.example.com")})
	_, err := s.datastore.Q.UpdateOAuthClient(s.T().Context(), db.UpdateOAuthClientParams{
		ClientID:           result.Client.ClientID,
		SetDefaultResource: true,
		DefaultResource:    testResource("https://changed.example.com"),
	})
	s.Require().NoError(err)

	refreshed := s.mustRefreshAt("http://localhost:8080", result.Client.ClientID, result.TokenResponse.RefreshToken)
	s.Equal(`["https://original.example.com"]`, s.accessTokenRawAud(refreshed.AccessToken),
		"a refresh reissues for the resource stored on the token, not the client's new default")
	s.Equal(testResource("https://original.example.com"), s.tokenRowResource(s.datastore, refreshed.RefreshToken))

	// Clearing the default (what --clear-default-resource does) is just as
	// invisible to the existing grant.
	cleared, err := s.datastore.Q.UpdateOAuthClient(s.T().Context(), db.UpdateOAuthClientParams{
		ClientID:           result.Client.ClientID,
		SetDefaultResource: true,
	})
	s.Require().NoError(err)
	s.False(cleared.DefaultResource.Valid)
	again := s.mustRefreshAt("http://localhost:8080", result.Client.ClientID, refreshed.RefreshToken)
	s.Equal(`["https://original.example.com"]`, s.accessTokenRawAud(again.AccessToken))
}

// TestUpdateOAuthClientLeavesDefaultResourceAlone: an update that doesn't ask
// to change the default resource doesn't touch it.
func (s *OAuthFlowSuite) TestUpdateOAuthClientLeavesDefaultResourceAlone() {
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:        s.mustGenerateRandomString(8),
		Name:            s.mustGenerateRandomString(8),
		RedirectUris:    []string{"http://localhost:8080/callback"},
		AllowedScopes:   []string{"openid"},
		DefaultResource: testResource("https://kept.example.com"),
	})
	updated, err := s.datastore.Q.UpdateOAuthClient(s.T().Context(), db.UpdateOAuthClientParams{
		ClientID: client.ClientID,
		Name:     sql.NullString{String: "Renamed", Valid: true},
	})
	s.Require().NoError(err)
	s.Equal("Renamed", updated.Name)
	s.Equal(testResource("https://kept.example.com"), updated.DefaultResource)
}

// TestAccessTokenFormat: header typ at+jwt and a client_id claim holding the
// public client_id (RFC 9068), on tokens from code exchange and refresh. The
// ID token is unchanged: aud is the client_id.
func (s *OAuthFlowSuite) TestAccessTokenFormat() {
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:        s.mustGenerateRandomString(8),
		Name:            s.mustGenerateRandomString(8),
		RedirectUris:    []string{"http://localhost:8080/callback"},
		AllowedScopes:   []string{"openid", "profile", "email"},
		IsConfidential:  false,
		DefaultResource: testResource("https://api.example.com"),
	})
	refreshed := s.mustRefreshAt("http://localhost:8080", result.Client.ClientID, result.TokenResponse.RefreshToken)

	wantClientID, err := json.Marshal(result.Client.ClientID)
	s.Require().NoError(err)
	for name, token := range map[string]string{"exchange": result.TokenResponse.AccessToken, "refresh": refreshed.AccessToken} {
		s.Equal(`"at+jwt"`, string(s.jwtSegmentJSON(token, 0)["typ"]), name)
		s.Equal(string(wantClientID), string(s.jwtSegmentJSON(token, 1)["client_id"]), name)
	}

	idToken := result.TokenResponse.IDToken
	s.Require().NotEmpty(idToken)
	s.NotEqual(`"at+jwt"`, string(s.jwtSegmentJSON(idToken, 0)["typ"]), "an ID token must not be typed as an access token")
	s.Equal(`["`+result.Client.ClientID+`"]`, string(s.jwtSegmentJSON(idToken, 1)["aud"]), "ID token aud is the client_id")
}

// TestUserInfoRefusesTokenWithoutOpenID: userinfo serves only tokens granted
// openid. A token for some API, without it, is refused like an invalid one.
func (s *OAuthFlowSuite) TestUserInfoRefusesTokenWithoutOpenID() {
	result := s.mustCompleteOAuthFlow(db.CreateOAuthClientParams{
		ClientID:        s.mustGenerateRandomString(8),
		Name:            s.mustGenerateRandomString(8),
		RedirectUris:    []string{"http://localhost:8080/callback"},
		AllowedScopes:   []string{"openid", "profile", "email"},
		IsConfidential:  false,
		DefaultResource: testResource("https://api.example.com"),
	}, "profile email")
	s.Empty(result.TokenResponse.IDToken, "no openid, no ID token")

	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/oauth/userinfo", nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+result.TokenResponse.AccessToken)
	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusUnauthorized, resp.StatusCode)
	s.Contains(resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`)
	var body map[string]string
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	s.Equal("invalid_token", body["error"])
}

// TestAdminAPIRequiresIssuerAudience: the admin API accepts a token only when
// its aud is identity's issuer. The same admin scope on a token minted for
// another API is refused; a client with no default resource gets an
// issuer-audience token and is let in.
func (s *OAuthFlowSuite) TestAdminAPIRequiresIssuerAudience() {
	listUsers := func(token string) *http.Response {
		req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/admin/users", nil)
		s.Require().NoError(err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := s.httpClient.Do(req)
		s.Require().NoError(err)
		return resp
	}
	register := func(defaultResource sql.NullString) (string, string) {
		secret := s.mustGenerateRandomString(32)
		client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
			ClientID:        s.mustGenerateRandomString(8),
			ClientSecret:    sql.NullString{String: secret, Valid: true},
			Name:            s.mustGenerateRandomString(8),
			RedirectUris:    []string{"http://localhost:8080/callback"},
			AllowedScopes:   []string{"admin:users:read"},
			IsConfidential:  true,
			DefaultResource: defaultResource,
		})
		return client.ClientID, secret
	}

	otherID, otherSecret := register(testResource("https://api.example.com"))
	otherToken := s.mustGetClientCredentialsToken(otherID, otherSecret, "admin:users:read")
	s.Equal(`["https://api.example.com"]`, s.accessTokenRawAud(otherToken))
	resp := listUsers(otherToken)
	defer resp.Body.Close()
	s.Equal(http.StatusUnauthorized, resp.StatusCode, "a token for another API must not reach the admin API")
	var body map[string]string
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&body))
	s.Equal("invalid_token", body["error"])

	ownID, ownSecret := register(sql.NullString{})
	ownToken := s.mustGetClientCredentialsToken(ownID, ownSecret, "admin:users:read")
	s.Equal(`["http://localhost:8080"]`, s.accessTokenRawAud(ownToken), "no default resource: the token is for identity itself")
	resp = listUsers(ownToken)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

// TestConsentUpsertKeyedByResource: consents are keyed by (user, client,
// resource) with NULL as a value, so re-consenting with no resource updates the
// one row rather than adding another -- the behavior the old (user, client)
// key had.
func (s *OAuthFlowSuite) TestConsentUpsertKeyedByResource() {
	ctx := s.T().Context()
	client := s.mustRegisterOAuthClient(db.CreateOAuthClientParams{
		ClientID:      s.mustGenerateRandomString(8),
		Name:          s.mustGenerateRandomString(8),
		RedirectUris:  []string{"http://localhost:8080/callback"},
		AllowedScopes: []string{"openid", "profile"},
	})
	user := s.mustRegisterUser(s.mustGenerateAlphanumericString(10), s.mustGenerateRandomString(12),
		s.mustGenerateAlphanumericString(10)+"@example.com")

	for _, scopes := range [][]string{{"openid"}, {"openid", "profile"}} {
		s.Require().NoError(s.datastore.Q.UpsertUserConsent(ctx, db.UpsertUserConsentParams{
			UserID: user.ID, ClientID: client.ID, Scopes: scopes,
		}))
	}
	var rows int
	s.Require().NoError(s.datastore.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM oauth_user_consents WHERE user_id = $1 AND client_id = $2`, user.ID, client.ID).Scan(&rows))
	s.Equal(1, rows)

	consent, err := s.datastore.Q.GetUserConsent(ctx, db.GetUserConsentParams{UserID: user.ID, ClientID: client.ID})
	s.Require().NoError(err)
	s.Equal([]string{"openid", "profile"}, consent.Scopes)
	s.False(consent.Resource.Valid)
}
