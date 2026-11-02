package httpserver

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/views"
	"github.com/google/uuid"
)

// Self-service account deletion.
//
// Deleting is two-phase, like deactivation plus a deadline: POST
// /oauth/delete-account deactivates the user at once (every app loses access,
// every token is revoked, every session ends) and stamps
// deletion_requested_at. The cleanup worker erases the row once
// accountDeletionGracePeriod has passed; the delete cascades through every
// user-owned table, and the avatar file is removed first. Until then the user
// can sign in here and reactivate, which cancels the deletion.
//
// An app can send the user here and get them back afterwards: it passes its
// client_id and one of its registered redirect_uris, and after deletion the
// browser is sent to that URI with account_deleted=true. That is how the
// Footstrike iOS app closes its in-app browser sheet. The pair is checked
// against the registered client (exact string match, never a metadata-document
// client) so this can't be used as an open redirect; an invalid pair is
// dropped and the user sees the "account deleted" page instead.

// accountDeletionGracePeriod is how long a deleted account stays recoverable
// before it is erased. It matches Footstrike's account-erasure grace period.
const accountDeletionGracePeriod = 30 * 24 * time.Hour

// accountErasureTimeout bounds one erasure sweep, like cleanupSweepTimeout.
const accountErasureTimeout = 30 * time.Second

// Form/query fields carrying the app to return to after deletion.
const (
	deleteReturnClientIDField    = "client_id"
	deleteReturnRedirectURIField = "redirect_uri"
)

// erasureDateFor is the day a deletion requested at requestedAt becomes
// permanent, formatted for display.
func erasureDateFor(requestedAt time.Time) string {
	return requestedAt.Add(accountDeletionGracePeriod).UTC().Format("January 2, 2006")
}

// deletionReturn is the validated app to send the user back to after deletion.
type deletionReturn struct {
	clientID    string
	redirectURI string
	appName     string
}

// resolveDeletionReturn validates the client_id/redirect_uri pair carried on r.
// It returns nil (go to the identity "deleted" page instead) unless the client
// is a registered one and redirect_uri is exactly one of its redirect URIs.
func (s *Server) resolveDeletionReturn(ctx context.Context, r *http.Request) *deletionReturn {
	clientID := r.FormValue(deleteReturnClientIDField)
	redirectURI := r.FormValue(deleteReturnRedirectURIField)
	if clientID == "" || redirectURI == "" || len(clientID) > 512 || len(redirectURI) > 2048 {
		return nil
	}
	client, err := s.datastore.Q.GetOAuthClientByClientID(ctx, clientID)
	if err != nil || client.Kind == clientKindCIMD {
		return nil
	}
	// Exact match only: wildcard and loopback entries are patterns for the
	// authorization flow, not addresses to send a signed-out browser to.
	if !slices.Contains(client.RedirectUris, redirectURI) || strings.Contains(redirectURI, "*") {
		return nil
	}
	return &deletionReturn{clientID: clientID, redirectURI: redirectURI, appName: client.Name}
}

// url is the redirect target: the registered URI with account_deleted=true.
func (d *deletionReturn) url() string {
	u, err := url.Parse(d.redirectURI)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("account_deleted", "true")
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Server) renderDeleteAccount(w http.ResponseWriter, r *http.Request, user db.AuthUser, ret *deletionReturn, status int, errMsg string) {
	data := views.DeleteAccountView{
		Username:    user.Username,
		Email:       user.Email,
		ErasureDate: erasureDateFor(time.Now()),
		Error:       errMsg,
		CSRFToken:   s.ensureCSRFToken(w, r),
	}
	if user.DeletionRequestedAt.Valid {
		data.AlreadyScheduledFor = erasureDateFor(user.DeletionRequestedAt.Time)
	}
	if ret != nil {
		data.ClientID = ret.clientID
		data.RedirectURI = ret.redirectURI
		data.AppName = ret.appName
	}
	if status != 0 {
		w.WriteHeader(status)
	}
	if err := views.DeleteAccount(data).Render(r.Context(), w); err != nil {
		log.Printf("[ERROR] renderDeleteAccount: %v", err)
	}
}

// HandleDeleteAccountGet godoc
// @Summary      Show delete account page
// @Description  Explains what deleting the account does and asks for the password. Optional client_id and redirect_uri name an app (and one of its registered redirect URIs) to return to afterwards.
// @Tags         account
// @Produce      html
// @Param        client_id query string false "Client to return to after deletion"
// @Param        redirect_uri query string false "Registered redirect URI of that client"
// @Success      200 {string} string "HTML delete account page"
// @Router       /delete-account [get]
func (s *Server) HandleDeleteAccountGet(w http.ResponseWriter, r *http.Request) {
	user, ok := userFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}
	s.renderDeleteAccount(w, r, user, s.resolveDeletionReturn(r.Context(), r), 0, "")
}

// HandleDeleteAccountPost godoc
// @Summary      Delete user account
// @Description  Deactivates the account immediately and schedules it for permanent erasure after 30 days. Reactivating within that window cancels the deletion.
// @Tags         account
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        password formData string true "Password for verification"
// @Param        client_id formData string false "Client to return to after deletion"
// @Param        redirect_uri formData string false "Registered redirect URI of that client"
// @Success      200 {string} string "Account deleted page"
// @Success      302 {string} string "Redirect to the app's redirect URI with account_deleted=true"
// @Failure      401 {string} string "Invalid password"
// @Router       /delete-account [post]
func (s *Server) HandleDeleteAccountPost(w http.ResponseWriter, r *http.Request) {
	user, ok := userFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}
	ret := s.resolveDeletionReturn(r.Context(), r)

	password := r.FormValue("password")
	if password == "" {
		s.renderDeleteAccount(w, r, user, ret, http.StatusBadRequest, "Enter your password to delete your account.")
		return
	}
	valid, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		log.Printf("[ERROR] HandleDeleteAccountPost: verify password: %v", err)
		s.renderDeleteAccount(w, r, user, ret, http.StatusInternalServerError, "An error occurred. Please try again.")
		return
	}
	if !valid {
		s.renderDeleteAccount(w, r, user, ret, http.StatusUnauthorized, "Password is incorrect.")
		return
	}

	if err := s.datastore.Q.RequestUserDeletion(r.Context(), user.ID); err != nil {
		log.Printf("[ERROR] HandleDeleteAccountPost: request deletion: %v", err)
		s.renderDeleteAccount(w, r, user, ret, http.StatusInternalServerError, "An error occurred while deleting your account. Please try again.")
		return
	}

	// Cut off every app and every browser now. Failures here are logged, not
	// fatal: the account is already inactive, so tokens and sessions are
	// rejected on use anyway.
	userIDNullable := uuid.NullUUID{UUID: user.ID, Valid: true}
	if err := s.datastore.Q.RevokeAllUserTokens(r.Context(), db.RevokeAllUserTokensParams{UserID: userIDNullable, Reason: string(revokedLogout)}); err != nil {
		log.Printf("[ERROR] HandleDeleteAccountPost: revoke tokens: %v", err)
	}
	if err := s.datastore.Q.DeleteAllUserSessions(r.Context(), user.ID); err != nil {
		log.Printf("[ERROR] HandleDeleteAccountPost: delete sessions: %v", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.isSecureContext(),
		SameSite: http.SameSiteLaxMode,
	})

	s.debugf("HandleDeleteAccountPost: user %s scheduled for deletion", user.Username)

	if ret != nil {
		if target := ret.url(); target != "" {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
	}
	requestedAt := time.Now()
	if user.DeletionRequestedAt.Valid {
		requestedAt = user.DeletionRequestedAt.Time
	}
	if err := views.AccountDeleted(views.AccountDeletedView{ErasureDate: erasureDateFor(requestedAt)}).Render(r.Context(), w); err != nil {
		log.Printf("[ERROR] HandleDeleteAccountPost: render: %v", err)
	}
}

// runAccountErasure permanently erases every account whose deletion was
// requested more than accountDeletionGracePeriod before now: the avatar file
// first, then the row (cascading through every user-owned table). A user
// whose avatar can't be removed is skipped and retried on the next sweep, so
// no file is ever orphaned. It returns how many accounts were erased.
func (s *Server) runAccountErasure(ctx context.Context, now time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, accountErasureTimeout)
	defer cancel()

	cutoff := now.Add(-accountDeletionGracePeriod)
	due, err := s.datastore.Q.ListUsersDueForErasure(ctx, cutoff)
	if err != nil {
		log.Printf("[ERROR] account erasure: list due accounts: %v", err)
		return 0, err
	}

	var lastErr error
	erased := 0
	for _, u := range due {
		if u.Picture.Valid && u.Picture.String != "" && s.avatarService != nil {
			if err := s.avatarService.Delete(ctx, u.Picture.String); err != nil {
				log.Printf("[ERROR] account erasure: delete avatar for user %s: %v (will retry)", u.ID, err)
				lastErr = err
				continue
			}
		}
		n, err := s.datastore.Q.EraseUser(ctx, db.EraseUserParams{ID: u.ID, Cutoff: cutoff})
		if err != nil {
			log.Printf("[ERROR] account erasure: erase user %s: %v", u.ID, err)
			lastErr = err
			continue
		}
		if n == 1 {
			erased++
			log.Printf("account erasure: erased user %s", u.ID)
		}
	}
	return erased, lastErr
}
