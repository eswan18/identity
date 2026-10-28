package httpserver

import (
	"context"
	"log"
	"net/http"
	"net/url"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/eswan18/identity/pkg/views"
)

// handleRegisterGet godoc
// @Summary      Show registration page
// @Description  Displays the registration form for creating a new user account, carrying the OAuth authorization request (if any) through the registration flow.
// @Tags         authentication
// @Produce      html
// @Param        authorize_query     query     string  false "The original /oauth/authorize query string, when sign-up is part of an OAuth flow"
// @Success      200 {string} string "HTML registration page"
// @Router       /register [get]
func (s *Server) HandleRegisterGet(w http.ResponseWriter, r *http.Request) {
	view := views.RegisterView{
		AuthorizeQuery: string(carriedAuthorizeRequest(r)),
		CSRFToken:      s.ensureCSRFToken(w, r),
	}
	if err := views.Register(view).Render(r.Context(), w); err != nil {
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
// @Param        authorize_query   formData  string  false "The original /oauth/authorize query string, when sign-up is part of an OAuth flow"
// @Success      302 {string} string "Redirect to login page on success"
// @Failure      400 {string} string "Invalid request parameters or validation error"
// @Failure      409 {string} string "Username or email already exists"
// @Router       /register [post]
func (s *Server) HandleRegisterPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")
	// The authorization request, carried whole so every re-render below and the
	// redirect to login keep all of it.
	request := carriedAuthorizeRequest(r)

	// refuse re-renders the form with an error, keeping what the user typed and
	// the authorization request.
	refuse := func(status int, msg string) {
		s.renderRegisterError(w, r, status, msg, views.RegisterView{
			Username:       username,
			Email:          email,
			AuthorizeQuery: string(request),
		})
	}

	// Validate required fields
	if username == "" || email == "" || password == "" {
		refuse(http.StatusBadRequest, "All fields are required")
		return
	}

	// Validate the username format before anything else touches it. Until this
	// check existed, self-service registration accepted any non-empty string,
	// including HTML that would later be interpolated into the verification
	// email sent to this address (see sendVerificationEmail below).
	if err := auth.ValidateUsername(username); err != nil {
		refuse(http.StatusBadRequest, err.Error())
		return
	}

	// Validate password match
	if password != confirmPassword {
		refuse(http.StatusBadRequest, "Passwords do not match")
		return
	}

	// Validate password requirements
	if err := auth.ValidatePassword(password, username); err != nil {
		refuse(http.StatusBadRequest, err.Error())
		return
	}

	// Hash password
	hash, err := auth.HashPassword(password)
	if err != nil {
		refuse(http.StatusInternalServerError, "An error occurred while creating your account")
		return
	}

	// Create user
	user, err := s.datastore.Q.CreateUser(context.Background(), db.CreateUserParams{
		Username:     username,
		Email:        email,
		PasswordHash: hash,
	})
	if err != nil {
		log.Println("Error creating user:", err)
		refuse(http.StatusInternalServerError, "An error occurred while creating your account")
		return
	}

	// Send verification email (don't block registration on failure)
	if err := s.sendVerificationEmail(r.Context(), user.ID, user.Email, user.Username); err != nil {
		log.Printf("Failed to send verification email to %s: %v", user.Email, err)
		// Continue with registration - user can request new verification email later
	}

	// On to sign-in, still carrying the authorization request.
	http.Redirect(w, r, request.loginURL(url.Values{"registered": {"true"}}), http.StatusFound)
}

// renderRegisterError renders the registration page with an error message, preserving user input and the authorization request.
// It handles template execution errors gracefully by falling back to the error template.
func (s *Server) renderRegisterError(w http.ResponseWriter, r *http.Request, statusCode int, errorMsg string, data views.RegisterView) {
	csrfToken := s.ensureCSRFToken(w, r)
	w.WriteHeader(statusCode)
	err := views.Register(views.RegisterView{
		Error:          errorMsg,
		Username:       data.Username,
		Email:          data.Email,
		AuthorizeQuery: data.AuthorizeQuery,
		CSRFToken:      csrfToken,
	}).Render(r.Context(), w)
	if err != nil {
		// Fallback to error template if register template fails
		err = views.Error(views.ErrorView{
			Title:     "Internal Server Error",
			Message:   "An error occurred while rendering the registration page",
			Details:   err.Error(),
			ErrorCode: "500",
		}).Render(r.Context(), w)
		if err != nil {
			// Last resort: plain text error
			http.Error(w, "An error occurred while rendering the error page", http.StatusInternalServerError)
		}
	}
}
