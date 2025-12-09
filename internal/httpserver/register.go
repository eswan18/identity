package httpserver

import (
	"context"
	"log"
	"net/http"
	"net/url"

	"github.com/eswan18/identity/internal/auth"
	"github.com/eswan18/identity/internal/db"
)

// handleRegisterGet godoc
// @Summary      Show registration page
// @Description  Displays the registration form for creating a new user account. Accepts OAuth parameters to preserve them through the registration flow.
// @Tags         authentication
// @Produce      html
// @Param        client_id           query     string  false "OAuth client identifier (preserved through flow)"
// @Param        redirect_uri        query     string  false "OAuth redirect URI (preserved through flow)"
// @Param        state               query     string  false "OAuth state parameter (preserved through flow)"
// @Param        scope               query     string  false "OAuth scope (preserved through flow)"
// @Param        code_challenge      query     string  false "PKCE code challenge (preserved through flow)"
// @Param        code_challenge_method query   string  false "PKCE challenge method (preserved through flow)"
// @Success      200 {string} string "HTML registration page"
// @Router       /register [get]
func (s *Server) handleRegisterGet(w http.ResponseWriter, r *http.Request) {
	// Extract OAuth parameters from query string to preserve them
	oauthParams := RegisterPageData{
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		State:               r.URL.Query().Get("state"),
		Scope:               r.URL.Query().Get("scope"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
	}
	if err := s.registerTemplate.Execute(w, oauthParams); err != nil {
		http.Error(w, "An error occurred while rendering the registration page", http.StatusInternalServerError)
	}
}

// handleRegisterPost godoc
// @Summary      Register new user
// @Description  Creates a new user account with username, email, and password
// @Tags         authentication
// @Accept       application/x-www-form-urlencoded
// @Produce      html
// @Param        username          formData  string  true  "Desired username"
// @Param        email             formData  string  true  "User email address"
// @Param        password          formData  string  true  "User password (min 8 characters)"
// @Param        confirm_password  formData  string  true  "Password confirmation"
// @Success      302 {string} string "Redirect to login page on success"
// @Failure      400 {string} string "Invalid request parameters or validation error"
// @Failure      409 {string} string "Username or email already exists"
// @Router       /register [post]
func (s *Server) handleRegisterPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	// Validate required fields
	if username == "" || email == "" || password == "" {
		s.renderRegisterError(w, http.StatusBadRequest, "All fields are required", RegisterPageData{
			Username: username,
			Email:    email,
		})
		return
	}

	// Validate password match
	if password != confirmPassword {
		s.renderRegisterError(w, http.StatusBadRequest, "Passwords do not match", RegisterPageData{
			Username: username,
			Email:    email,
		})
		return
	}

	// Validate password length
	if len(password) < 8 {
		s.renderRegisterError(w, http.StatusBadRequest, "Password must be at least 8 characters", RegisterPageData{
			Username: username,
			Email:    email,
		})
		return
	}

	// Hash password
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.renderRegisterError(w, http.StatusInternalServerError, "An error occurred while creating your account", RegisterPageData{
			Username: username,
			Email:    email,
		})
		return
	}

	// Extract OAuth parameters from form to preserve them
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	scope := r.FormValue("scope")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	// Create user
	_, err = s.datastore.Q.CreateUser(context.Background(), db.CreateUserParams{
		Username:     username,
		Email:        email,
		PasswordHash: hash,
	})
	if err != nil {
		log.Println("Error creating user:", err)
		s.renderRegisterError(w, http.StatusInternalServerError, "An error occurred while creating your account", RegisterPageData{
			Username:            username,
			Email:               email,
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			State:               state,
			Scope:               scope,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
		})
		return
	}

	// Build redirect URL to login with OAuth params preserved
	loginURL := "/login?registered=true"
	if redirectURI != "" {
		loginURL += "&redirect_uri=" + url.QueryEscape(redirectURI)
	}
	if clientID != "" {
		loginURL += "&client_id=" + url.QueryEscape(clientID)
	}
	if state != "" {
		loginURL += "&state=" + url.QueryEscape(state)
	}
	if scope != "" {
		loginURL += "&scope=" + url.QueryEscape(scope)
	}
	if codeChallenge != "" {
		loginURL += "&code_challenge=" + url.QueryEscape(codeChallenge)
	}
	if codeChallengeMethod != "" {
		loginURL += "&code_challenge_method=" + url.QueryEscape(codeChallengeMethod)
	}

	http.Redirect(w, r, loginURL, http.StatusFound)
}

// renderRegisterError renders the registration page with an error message, preserving user input and OAuth parameters.
// It handles template execution errors gracefully by falling back to the error template.
func (s *Server) renderRegisterError(w http.ResponseWriter, statusCode int, errorMsg string, data RegisterPageData) {
	w.WriteHeader(statusCode)
	err := s.registerTemplate.Execute(w, RegisterPageData{
		Error:               errorMsg,
		Username:            data.Username,
		Email:               data.Email,
		ClientID:            data.ClientID,
		RedirectURI:         data.RedirectURI,
		State:               data.State,
		Scope:               data.Scope,
		CodeChallenge:       data.CodeChallenge,
		CodeChallengeMethod: data.CodeChallengeMethod,
	})
	if err != nil {
		// Fallback to error template if register template fails
		err = s.errorTemplate.Execute(w, ErrorPageData{
			Title:     "Internal Server Error",
			Message:   "An error occurred while rendering the registration page",
			Details:   err.Error(),
			ErrorCode: "500",
		})
		if err != nil {
			// Last resort: plain text error
			http.Error(w, "An error occurred while rendering the error page", http.StatusInternalServerError)
		}
	}
}
