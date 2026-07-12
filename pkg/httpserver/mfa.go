package httpserver

import (
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/mfa"
	"github.com/eswan18/identity/pkg/views"
	"github.com/google/uuid"
)

const mfaPendingExpiresIn = 5 * time.Minute

// oauthParamsFromPending lifts the OAuth authorization parameters stored on a pending
// MFA row into the common LoginPageData carrier.
func oauthParamsFromPending(p db.AuthMfaPending) LoginPageData {
	return LoginPageData{
		ClientID:            p.ClientID.String,
		RedirectURI:         p.RedirectUri.String,
		State:               p.State.String,
		Scope:               p.Scope,
		CodeChallenge:       p.CodeChallenge.String,
		CodeChallengeMethod: p.CodeChallengeMethod.String,
		Nonce:               p.Nonce.String,
	}
}

// mfaPageData assembles the MFA view from the pending ID, the OAuth context,
// and an optional error message.
//
// The OAuth authorization parameters are carried through the page as hidden form
// fields so the originating authorization request survives even if the server-side
// pending row is gone by the time the code is submitted — because it expired during
// code entry, or a duplicate/replayed submit already consumed it. Without this, a lost
// pending row strips the OAuth context and the user is bounced to a context-free login
// (and, after re-authenticating, dumped on the account page instead of the app).
func mfaPageData(pendingID string, p LoginPageData, errMsg, csrfToken string) views.MFAView {
	return views.MFAView{
		Error:               errMsg,
		PendingID:           pendingID,
		ClientID:            p.ClientID,
		RedirectURI:         p.RedirectURI,
		State:               p.State,
		Scope:               p.Scope,
		CodeChallenge:       p.CodeChallenge,
		CodeChallengeMethod: p.CodeChallengeMethod,
		Nonce:               p.Nonce,
		CSRFToken:           csrfToken,
	}
}

// HandleMFAGet displays the MFA code entry form.
func (s *Server) HandleMFAGet(w http.ResponseWriter, r *http.Request) {
	pendingID := r.URL.Query().Get("pending")
	if pendingID == "" {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Verify the pending MFA session exists and is valid, and source the OAuth context
	// from it (server-side, authoritative) so the rendered form can carry it on submit.
	pending, err := s.datastore.Q.GetMFAPending(r.Context(), pendingID)
	if err != nil {
		s.debugf("HandleMFAGet: Invalid or expired pending MFA session: %v", err)
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	if err := views.MFA(mfaPageData(pendingID, oauthParamsFromPending(pending), "", s.ensureCSRFToken(w, r))).Render(r.Context(), w); err != nil {
		log.Printf("[ERROR] HandleMFAGet: Failed to render MFA page: %v", err)
	}
}

// HandleMFAPost validates the MFA code and completes the login flow.
func (s *Server) HandleMFAPost(w http.ResponseWriter, r *http.Request) {
	pendingID := r.FormValue("pending_id")
	code := r.FormValue("code")

	// OAuth context echoed back by the MFA form (rendered there from the pending row).
	// This is used only as a fallback to keep the flow alive when the pending row can no
	// longer be found; whenever the row is present it remains the authoritative source.
	// Either way, /oauth/authorize re-validates client_id, redirect_uri and scope, so a
	// tampered field cannot escalate — it just produces a validation error.
	formParams := LoginPageData{
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		State:               r.FormValue("state"),
		Scope:               strings.Split(r.FormValue("scope"), " "),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		Nonce:               r.FormValue("nonce"),
	}

	if pendingID == "" {
		s.resumeMFAFlow(w, r, formParams)
		return
	}

	// Get the pending MFA session.
	pending, err := s.datastore.Q.GetMFAPending(r.Context(), pendingID)
	if err != nil {
		// The pending row is gone: it expired while the user entered their code, or a
		// duplicate/replayed submit already consumed it. Do NOT discard the OAuth
		// context — resume the flow so the user returns to the originating app instead
		// of being stranded on a context-free login (and then the account page).
		s.debugf("HandleMFAPost: pending MFA session missing/expired (%v); resuming with carried OAuth context", err)
		s.resumeMFAFlow(w, r, formParams)
		return
	}

	// With the pending row in hand, it is the authoritative source of OAuth params.
	pendingParams := oauthParamsFromPending(pending)

	// Get the user's MFA secret.
	mfaStatus, err := s.datastore.Q.GetUserMFAStatus(r.Context(), pending.UserID)
	if err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to get MFA status: %v", err)
		s.renderMFAError(w, r, http.StatusInternalServerError, "An error occurred", pendingID, pendingParams)
		return
	}

	if !mfaStatus.MfaEnabled || !mfaStatus.MfaSecret.Valid {
		log.Printf("[ERROR] HandleMFAPost: MFA not enabled for user")
		s.resumeMFAFlow(w, r, pendingParams)
		return
	}

	// Validate the TOTP code. A wrong code leaves the pending row intact so the user can
	// retry within the validity window.
	if !mfa.ValidateCode(mfaStatus.MfaSecret.String, code) {
		s.debugf("HandleMFAPost: Invalid MFA code for user: %v", pending.UserID)
		s.renderMFAError(w, r, http.StatusUnauthorized, "Invalid verification code", pendingID, pendingParams)
		return
	}

	// Consume the pending MFA session (single use).
	if err := s.datastore.Q.DeleteMFAPending(r.Context(), pendingID); err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to delete pending MFA session: %v", err)
	}

	// Create authenticated session.
	session, err := s.createSession(r.Context(), pending.UserID)
	if err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to create session: %v", err)
		s.renderMFAError(w, r, http.StatusInternalServerError, "An error occurred", pendingID, pendingParams)
		return
	}

	// Update last login timestamp (non-fatal on error).
	if err := s.datastore.Q.UpdateUserLastLogin(r.Context(), pending.UserID); err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to update last login time: %v", err)
	}

	s.setSessionCookie(w, session)

	// Resume using the pending row's authoritative OAuth params.
	s.redirectAfterAuth(w, r, pendingParams)
}

// resumeMFAFlow recovers the login flow when the pending MFA row is no longer available
// at submit time. It must never discard the OAuth context.
//
// When a client initiated the flow, the user is routed back through /oauth/authorize:
//   - if a session already exists (a duplicate submit already completed OTP), authorize
//     finishes the flow and returns the user to the app;
//   - otherwise authorize sends them to the login page with the OAuth parameters
//     preserved, so a fresh password + OTP still lands them back on the app.
//
// For a direct (non-OAuth) login there is no app context to preserve, so the user goes
// to account settings if already authenticated, or the login page if not.
func (s *Server) resumeMFAFlow(w http.ResponseWriter, r *http.Request, p LoginPageData) {
	if p.ClientID != "" {
		http.Redirect(w, r, buildAuthorizeURL(p), http.StatusFound)
		return
	}
	if _, err := s.getSessionFromCookie(r); err == nil {
		http.Redirect(w, r, "/oauth/account-settings", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/oauth/login", http.StatusFound)
}

// createMFAPendingSession creates a pending MFA session after password validation.
func (s *Server) createMFAPendingSession(r *http.Request, userID uuid.UUID, oauthParams LoginPageData) (string, error) {
	pendingID, err := generateRandomString(32)
	if err != nil {
		return "", err
	}

	params := db.CreateMFAPendingParams{
		ID:                  pendingID,
		UserID:              userID,
		ClientID:            sql.NullString{String: oauthParams.ClientID, Valid: oauthParams.ClientID != ""},
		RedirectUri:         sql.NullString{String: oauthParams.RedirectURI, Valid: oauthParams.RedirectURI != ""},
		State:               sql.NullString{String: oauthParams.State, Valid: oauthParams.State != ""},
		Scope:               oauthParams.Scope,
		CodeChallenge:       sql.NullString{String: oauthParams.CodeChallenge, Valid: oauthParams.CodeChallenge != ""},
		CodeChallengeMethod: sql.NullString{String: oauthParams.CodeChallengeMethod, Valid: oauthParams.CodeChallengeMethod != ""},
		ExpiresAt:           time.Now().Add(mfaPendingExpiresIn),
		Nonce:               sql.NullString{String: oauthParams.Nonce, Valid: oauthParams.Nonce != ""},
	}

	if err := s.datastore.Q.CreateMFAPending(r.Context(), params); err != nil {
		return "", err
	}

	return pendingID, nil
}

// renderMFAError renders the MFA page with an error message, preserving the OAuth
// context so a retry keeps the originating authorization request intact.
func (s *Server) renderMFAError(w http.ResponseWriter, r *http.Request, statusCode int, errorMsg string, pendingID string, p LoginPageData) {
	csrfToken := s.ensureCSRFToken(w, r)
	w.WriteHeader(statusCode)
	if err := views.MFA(mfaPageData(pendingID, p, errorMsg, csrfToken)).Render(r.Context(), w); err != nil {
		log.Printf("[ERROR] renderMFAError: Failed to render MFA page: %v", err)
	}
}
