package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/views"
	"github.com/google/uuid"
)

// Connected apps: the account page that lists the apps a user has given
// consent to and lets them disconnect one.
//
// An app is connected when the user has a remembered consent for it
// (oauth_user_consents), one row per resource it was approved for (spec
// section 8). A client the user never consented to is not listed, whatever
// tokens exist. Disconnecting deletes those consents, so using the app again
// asks for consent again, and revokes every live token the user holds for it
// (revokedUserDisconnected), so it loses access at once rather than when its
// access token expires: a refresh with a revoked refresh token is refused, and
// the access token stops passing introspection.
//
// Trusted (first-party) clients are never connected apps: they skip consent,
// so they have no consent rows, and the page's query ignores any left over
// from before the client was trusted. Disconnecting one is refused as not
// connected, the same as for an app the page does not list.

const connectedAppsPath = "/oauth/connected-apps"

// connectedAppsDateLayout is how the page shows dates. They are rendered on
// the server, which does not know the reader's time zone, so they are dates in
// UTC rather than times; the <time> element carries the exact instant.
const connectedAppsDateLayout = "Jan 2, 2006"

// HandleConnectedAppsGet renders the connected-apps page.
func (s *Server) HandleConnectedAppsGet(w http.ResponseWriter, r *http.Request) {
	user, ok := userFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, loginURLReturningTo(r), http.StatusFound)
		return
	}

	data := views.ConnectedAppsView{}
	switch r.URL.Query().Get("success") {
	case "disconnected":
		data.Success = "App disconnected. It can no longer access your account."
	}
	switch r.URL.Query().Get("error") {
	case "not_connected":
		data.Error = "That app is not connected to your account."
	case "confirm_required":
		data.Error = "Please confirm that you want to disconnect the app."
	case "disconnect_failed":
		data.Error = "Something went wrong disconnecting the app. Please try again."
	}

	apps, err := s.connectedApps(r.Context(), user.ID)
	if err != nil {
		log.Printf("[ERROR] HandleConnectedAppsGet: user %s: %v", user.ID, err)
		s.renderError(w, http.StatusInternalServerError, "Something Went Wrong",
			"Your connected apps could not be loaded. Please try again.", "")
		return
	}
	data.Apps = apps
	data.CSRFToken = s.ensureCSRFToken(w, r)

	if err := views.ConnectedApps(data).Render(r.Context(), w); err != nil {
		log.Printf("[ERROR] HandleConnectedAppsGet: failed to render: %v", err)
	}
}

// HandleConnectedAppsDisconnectPost disconnects one app from the signed-in
// user's account: in one transaction it deletes the user's consents for the
// client, revokes every live token they hold for it, and deletes codes issued
// to it for them that have not been exchanged yet (so one in flight cannot
// become a token afterwards).
//
// Everything is scoped to the signed-in user, so naming a client the user is
// not connected to -- another user's, or one that does not exist -- changes
// nothing and is reported as not connected.
func (s *Server) HandleConnectedAppsDisconnectPost(w http.ResponseWriter, r *http.Request) {
	user, ok := userFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}
	redirect := func(key, value string) {
		http.Redirect(w, r, connectedAppsPath+"?"+key+"="+value, http.StatusFound)
	}

	if r.FormValue("confirm") != "yes" {
		redirect("error", "confirm_required")
		return
	}
	clientID, err := uuid.Parse(r.FormValue("client"))
	if err != nil {
		redirect("error", "not_connected")
		return
	}

	disconnected, err := s.disconnectApp(r.Context(), user.ID, clientID)
	if err != nil {
		log.Printf("[ERROR] HandleConnectedAppsDisconnectPost: user %s, client %s: %v", user.ID, clientID, err)
		redirect("error", "disconnect_failed")
		return
	}
	if !disconnected {
		redirect("error", "not_connected")
		return
	}
	redirect("success", "disconnected")
}

// disconnectApp is the transaction behind HandleConnectedAppsDisconnectPost.
// It reports false, having changed nothing, when the user had no consent for
// the client.
func (s *Server) disconnectApp(ctx context.Context, userID, clientID uuid.UUID) (bool, error) {
	tx, err := s.datastore.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	q := s.datastore.Q.WithTx(tx)

	client, err := q.GetOAuthClientByID(ctx, clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading client: %w", err)
	}
	if client.Trusted {
		return false, nil
	}

	consents, err := q.DeleteUserConsentsForUserClient(ctx, db.DeleteUserConsentsForUserClientParams{
		UserID: userID, ClientID: clientID,
	})
	if err != nil {
		return false, fmt.Errorf("deleting consents: %w", err)
	}
	if consents == 0 {
		return false, nil
	}
	tokens, err := q.RevokeUserClientTokens(ctx, db.RevokeUserClientTokensParams{
		UserID: userID, ClientID: clientID, Reason: string(revokedUserDisconnected),
	})
	if err != nil {
		return false, fmt.Errorf("revoking tokens: %w", err)
	}
	codes, err := q.DeleteUnconsumedUserClientAuthorizationCodes(ctx, db.DeleteUnconsumedUserClientAuthorizationCodesParams{
		UserID: userID, ClientID: clientID,
	})
	if err != nil {
		return false, fmt.Errorf("deleting authorization codes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	log.Printf("connected apps: user %s disconnected client %s (%d consents deleted, %d tokens revoked, %d codes deleted)",
		userID, clientID, consents, tokens, codes)
	return true, nil
}

// connectedApps is the page's list: the user's consents grouped by client, in
// the query's order (by name).
func (s *Server) connectedApps(ctx context.Context, userID uuid.UUID) ([]views.ConnectedApp, error) {
	rows, err := s.datastore.Q.ListUserConnectedApps(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing consents: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	issued, err := s.datastore.Q.ListUserTokenLastIssued(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing token activity: %w", err)
	}
	lastIssued := make(map[uuid.UUID]time.Time, len(issued))
	for _, row := range issued {
		lastIssued[row.ClientID] = row.LastIssuedAt
	}
	return buildConnectedApps(rows, lastIssued), nil
}

// buildConnectedApps groups consent rows by client and describes each, with
// lastIssued (by client) as when the app was last used.
func buildConnectedApps(rows []db.ListUserConnectedAppsRow, lastIssued map[uuid.UUID]time.Time) []views.ConnectedApp {
	var apps []views.ConnectedApp
	index := map[uuid.UUID]int{}
	connectedAt := map[uuid.UUID]time.Time{}
	for _, row := range rows {
		i, seen := index[row.ClientUuid]
		if !seen {
			i = len(apps)
			index[row.ClientUuid] = i
			apps = append(apps, connectedAppHeader(row))
		}
		apps[i].Access = append(apps[i].Access, connectedAppAccess(row))
		if first, ok := connectedAt[row.ClientUuid]; !ok || row.CreatedAt.Before(first) {
			connectedAt[row.ClientUuid] = row.CreatedAt
		}
	}
	for clientID, i := range index {
		at := connectedAt[clientID]
		apps[i].ConnectedAt = at.UTC().Format(connectedAppsDateLayout)
		apps[i].ConnectedAtISO = at.UTC().Format(time.RFC3339)
		if used, ok := lastIssued[clientID]; ok {
			apps[i].LastUsed = used.UTC().Format(connectedAppsDateLayout)
			apps[i].LastUsedISO = used.UTC().Format(time.RFC3339)
		}
	}
	return apps
}

// connectedAppHeader names the app the way the consent screen did (see
// consentView): a registered client by its name; a metadata-document client
// by the host serving its document, with the name it gives itself as its
// claim and the document's URL in full.
func connectedAppHeader(row db.ListUserConnectedAppsRow) views.ConnectedApp {
	app := views.ConnectedApp{
		ClientRef: row.ClientUuid.String(),
		Name:      row.ClientName,
	}
	if row.ClientKind == clientKindCIMD {
		if host := urlHost(row.ClientID); host != "" {
			app.Name = host
		}
		app.ClaimedName = row.ClientName
		app.ClientURI = row.ClientID
	}
	return app
}

// connectedAppAccess describes one consent: the resource it is for and its
// scopes, with the descriptions the consent screen used. A scope that no
// longer has one (the resource's registry entry changed or went away) is shown
// as the raw scope rather than hidden, since the app still holds it.
func connectedAppAccess(row db.ListUserConnectedAppsRow) views.ConnectedAppAccess {
	var resource *resolvedResource
	access := views.ConnectedAppAccess{}
	if row.Resource.Valid {
		resource = &resolvedResource{URI: row.Resource.String, Scopes: map[string]string{}}
		if len(row.ResourceScopes) > 0 {
			if err := json.Unmarshal(row.ResourceScopes, &resource.Scopes); err != nil {
				log.Printf("[ERROR] connected apps: resource %s has unreadable scopes: %v", row.Resource.String, err)
			}
		}
		access.ResourceHost = resourceHost(row.Resource.String)
		access.ResourceName = access.ResourceHost
		if row.ResourceName.Valid && row.ResourceName.String != "" {
			access.ResourceName = row.ResourceName.String
		}
	}

	var seen []string
	for _, sc := range row.Scopes {
		if sc == "" || slices.Contains(seen, sc) {
			continue
		}
		seen = append(seen, sc)
		// The same lookup as consentScopeDescriptions, but keeping a scope
		// with no description.
		desc, ok := scopeDescriptionMap[sc]
		if !ok && resource != nil {
			desc, ok = resource.Scopes[sc]
		}
		if !ok {
			desc = sc
		}
		access.ScopeDescriptions = append(access.ScopeDescriptions, views.ScopeDescription{Scope: sc, Description: desc})
	}
	return access
}
