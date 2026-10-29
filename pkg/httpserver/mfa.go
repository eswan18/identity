package httpserver

import (
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/mfa"
	"github.com/eswan18/identity/pkg/views"
	"github.com/google/uuid"
)

const mfaPendingExpiresIn = 5 * time.Minute

// mfaPageData assembles the MFA view from the pending ID, the authorization
// request, and an optional error message.
//
// The authorization request is carried through the page as a hidden form field so
// it survives even if the server-side pending row is gone by the time the code is
// submitted — because it expired during code entry, or a duplicate/replayed submit
// already consumed it. Without this, a lost pending row strips the OAuth context and
// the user is bounced to a context-free login (and, after re-authenticating, dumped
// on the account page instead of the app).
//
// The page to return to after a direct sign-in (carriedReturnTo) rides along the
// same way, read from the request each time.
func mfaPageData(r *http.Request, pendingID string, request authorizeRequest, errMsg, csrfToken string) views.MFAView {
	return views.MFAView{
		Error:          errMsg,
		PendingID:      pendingID,
		AuthorizeQuery: string(request),
		ReturnTo:       carriedReturnTo(r),
		CSRFToken:      csrfToken,
	}
}

// HandleMFAGet displays the MFA code entry form.
func (s *Server) HandleMFAGet(w http.ResponseWriter, r *http.Request) {
	pendingID := r.URL.Query().Get("pending")
	if pendingID == "" {
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	// Verify the pending MFA session exists and is valid, and source the authorization
	// request from it (server-side, authoritative) so the rendered form can carry it on
	// submit.
	pending, err := s.datastore.Q.GetMFAPending(r.Context(), pendingID)
	if err != nil {
		s.debugf("HandleMFAGet: Invalid or expired pending MFA session: %v", err)
		http.Redirect(w, r, "/oauth/login", http.StatusFound)
		return
	}

	if err := views.MFA(mfaPageData(r, pendingID, authorizeRequest(pending.AuthorizeQuery.String), "", s.ensureCSRFToken(w, r))).Render(r.Context(), w); err != nil {
		log.Printf("[ERROR] HandleMFAGet: Failed to render MFA page: %v", err)
	}
}

// HandleMFAPost validates the MFA code and completes the login flow.
func (s *Server) HandleMFAPost(w http.ResponseWriter, r *http.Request) {
	pendingID := r.FormValue("pending_id")
	code := r.FormValue("code")

	// The authorization request echoed back by the MFA form (rendered there from the
	// pending row). This is used only as a fallback to keep the flow alive when the
	// pending row can no longer be found; whenever the row is present it remains the
	// authoritative source. Either way, /oauth/authorize re-validates the whole request,
	// so a tampered field cannot escalate — it just produces a validation error.
	formRequest := carriedAuthorizeRequest(r)

	if pendingID == "" {
		s.resumeMFAFlow(w, r, formRequest)
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
		s.resumeMFAFlow(w, r, formRequest)
		return
	}

	// With the pending row in hand, it is the authoritative source of the request.
	pendingRequest := authorizeRequest(pending.AuthorizeQuery.String)

	// Get the user's MFA secret.
	mfaStatus, err := s.datastore.Q.GetUserMFAStatus(r.Context(), pending.UserID)
	if err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to get MFA status: %v", err)
		s.renderMFAError(w, r, http.StatusInternalServerError, "An error occurred", pendingID, pendingRequest)
		return
	}

	if !mfaStatus.MfaEnabled || !mfaStatus.MfaSecret.Valid {
		log.Printf("[ERROR] HandleMFAPost: MFA not enabled for user")
		s.resumeMFAFlow(w, r, pendingRequest)
		return
	}

	// An empty submission is a mistake, not a guess, and must not cost budget.
	// HandleMFASetupPost already treats it this way; this path did not.
	if code == "" {
		s.renderMFAError(w, r, http.StatusBadRequest,
			"Please enter the verification code from your authenticator app.", pendingID, pendingRequest)
		return
	}

	// Take a unit of the account's failure budget before evaluating the code,
	// and hand it back below if the code turns out to be right. See
	// mfa_throttle.go for why the budget is per account rather than per pending
	// row or per IP, and why reserving beats peeking.
	if !s.chargeMFAAttempt(pending.UserID) {
		// Consume the pending row too. Leaving it would let guessing resume the
		// instant a token refills; destroying it means another password login is
		// needed first, which the per-IP limiter also bounds.
		if err := s.datastore.Q.DeleteMFAPending(r.Context(), pendingID); err != nil {
			log.Printf("[ERROR] HandleMFAPost: Failed to delete pending MFA session after exhausting attempts: %v", err)
		}
		// Redirect rather than re-render the MFA form. The pending row is gone,
		// so every field on that form is now dead -- re-rendering it invites the
		// user to enter a code that cannot be checked and bounces them silently
		// when they do. Send them to login, carrying the authorization request so
		// a fresh sign-in still returns them to the app, with a message that names
		// the most likely innocent cause: a device clock too far out of sync for
		// the ±1 window totp.Validate allows.
		http.Redirect(w, r,
			withReturnTo(pendingRequest.loginURL(url.Values{"error": {"mfa_throttled"}}), carriedReturnTo(r)),
			http.StatusFound)
		return
	}

	// Validate the TOTP code. A wrong code leaves the pending row intact so the user can
	// retry within the validity window.
	if !mfa.ValidateCode(mfaStatus.MfaSecret.String, code) {
		s.debugf("HandleMFAPost: Invalid MFA code for user: %v", pending.UserID)
		s.renderMFAError(w, r, http.StatusUnauthorized, "Invalid verification code", pendingID, pendingRequest)
		return
	}
	// Correct code: a successful verification clears the failure count.
	s.clearMFAAttempts(pending.UserID)

	// Consume the pending MFA session (single use).
	if err := s.datastore.Q.DeleteMFAPending(r.Context(), pendingID); err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to delete pending MFA session: %v", err)
	}

	// Create authenticated session.
	session, err := s.createSession(r.Context(), pending.UserID)
	if err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to create session: %v", err)
		s.renderMFAError(w, r, http.StatusInternalServerError, "An error occurred", pendingID, pendingRequest)
		return
	}

	// Update last login timestamp (non-fatal on error).
	if err := s.datastore.Q.UpdateUserLastLogin(r.Context(), pending.UserID); err != nil {
		log.Printf("[ERROR] HandleMFAPost: Failed to update last login time: %v", err)
	}

	s.setSessionCookie(w, session)

	// Resume using the pending row's authoritative authorization request.
	s.redirectAfterAuth(w, r, pendingRequest)
}

// resumeMFAFlow recovers the login flow when the pending MFA row is no longer available
// at submit time. It must never discard the OAuth context.
//
// When a client initiated the flow, the user is routed back through /oauth/authorize:
//   - if a session already exists (a duplicate submit already completed OTP), authorize
//     finishes the flow and returns the user to the app;
//   - otherwise authorize sends them to the login page with the authorization request
//     preserved, so a fresh password + OTP still lands them back on the app.
//
// For a direct (non-OAuth) login there is no app context to preserve, so the user goes
// to the page they asked for (or account settings) if already authenticated, or the
// login page, still carrying that page, if not.
func (s *Server) resumeMFAFlow(w http.ResponseWriter, r *http.Request, request authorizeRequest) {
	if request.inFlow() {
		http.Redirect(w, r, request.authorizeURL(), http.StatusFound)
		return
	}
	if _, err := s.getSessionFromCookie(r); err == nil {
		http.Redirect(w, r, directSignInDestination(r), http.StatusFound)
		return
	}
	http.Redirect(w, r, withReturnTo("/oauth/login", carriedReturnTo(r)), http.StatusFound)
}

// createMFAPendingSession creates a pending MFA session after password validation.
// The row keeps the authorization request the login form carried, so the flow
// resumes from the server's copy rather than the browser's.
func (s *Server) createMFAPendingSession(r *http.Request, userID uuid.UUID, request authorizeRequest) (string, error) {
	pendingID, err := generateRandomString(32)
	if err != nil {
		return "", err
	}

	params := db.CreateMFAPendingParams{
		ID:             pendingID,
		UserID:         userID,
		AuthorizeQuery: sql.NullString{String: string(request), Valid: request != ""},
		ExpiresAt:      time.Now().Add(mfaPendingExpiresIn),
	}

	if err := s.datastore.Q.CreateMFAPending(r.Context(), params); err != nil {
		return "", err
	}

	return pendingID, nil
}

// renderMFAError renders the MFA page with an error message, preserving the
// authorization request so a retry keeps it intact.
func (s *Server) renderMFAError(w http.ResponseWriter, r *http.Request, statusCode int, errorMsg string, pendingID string, request authorizeRequest) {
	csrfToken := s.ensureCSRFToken(w, r)
	w.WriteHeader(statusCode)
	if err := views.MFA(mfaPageData(r, pendingID, request, errorMsg, csrfToken)).Render(r.Context(), w); err != nil {
		log.Printf("[ERROR] renderMFAError: Failed to render MFA page: %v", err)
	}
}
