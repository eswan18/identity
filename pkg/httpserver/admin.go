package httpserver

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
)

// CreateUserRequest represents the request body for admin user creation
type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// CreateUserResponse represents the response for admin user creation (excludes password hash)
type CreateUserResponse struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	IsActive      bool   `json:"is_active"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     string `json:"created_at"`
}

// HandleAdminCreateUser godoc
// @Summary      Create a new user (Admin API)
// @Description  Creates a new user account. Requires admin:users:write scope.
// @Tags         admin
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request body CreateUserRequest true "User creation request"
// @Success      201 {object} CreateUserResponse "User created successfully"
// @Failure      400 {object} map[string]string "Invalid request"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      403 {object} map[string]string "Insufficient scope"
// @Failure      409 {object} map[string]string "Username or email already exists"
// @Router       /admin/users [post]
func (s *Server) HandleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	// Validate required fields
	if req.Username == "" {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request", "Username is required")
		return
	}
	if req.Email == "" {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request", "Email is required")
		return
	}
	if req.Password == "" {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request", "Password is required")
		return
	}

	// Validate username format (alphanumeric + underscore, 3-50 chars)
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_]{3,50}$`)
	if !usernameRegex.MatchString(req.Username) {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request",
			"Username must be 3-50 alphanumeric characters or underscores")
		return
	}

	// Validate email format
	emailRegex := regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	if !emailRegex.MatchString(req.Email) {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request", "Invalid email format")
		return
	}

	// Validate password using centralized validation (includes common password check)
	if err := auth.ValidatePassword(req.Password, req.Username); err != nil {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Hash password
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Admin create user: failed to hash password: %v", err)
		s.writeAdminError(w, http.StatusInternalServerError, "server_error", "Failed to process password")
		return
	}

	// Create user in database
	user, err := s.datastore.Q.CreateUser(r.Context(), db.CreateUserParams{
		Username:     req.Username,
		Email:        strings.ToLower(req.Email),
		PasswordHash: passwordHash,
	})
	if err != nil {
		// Check for unique constraint violations
		if strings.Contains(err.Error(), "auth_users_username_key") {
			s.writeAdminError(w, http.StatusConflict, "conflict", "Username already exists")
			return
		}
		if strings.Contains(err.Error(), "auth_users_email_key") {
			s.writeAdminError(w, http.StatusConflict, "conflict", "Email already exists")
			return
		}
		log.Printf("Admin create user: database error: %v", err)
		s.writeAdminError(w, http.StatusInternalServerError, "server_error", "Failed to create user")
		return
	}

	// Return created user (without password hash)
	response := CreateUserResponse{
		ID:            user.ID.String(),
		Username:      user.Username,
		Email:         user.Email,
		IsActive:      user.IsActive,
		EmailVerified: user.EmailVerified,
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}
