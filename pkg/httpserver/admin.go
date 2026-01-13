package httpserver

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/eswan18/identity/pkg/auth"
	"github.com/eswan18/identity/pkg/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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

// UserResponse represents a user in admin API responses
type UserResponse struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	IsActive      bool   `json:"is_active"`
	EmailVerified bool   `json:"email_verified"`
	MFAEnabled    bool   `json:"mfa_enabled"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// ListUsersResponse represents the response for listing users
type ListUsersResponse struct {
	Users      []UserResponse `json:"users"`
	Total      int64          `json:"total"`
	Limit      int            `json:"limit"`
	Offset     int            `json:"offset"`
	HasMore    bool           `json:"has_more"`
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

// HandleAdminListUsers godoc
// @Summary      List all users (Admin API)
// @Description  Returns a paginated list of all users. Requires admin:users:read scope.
// @Tags         admin
// @Produce      json
// @Security     BearerAuth
// @Param        limit  query int false "Number of users to return (default 20, max 100)"
// @Param        offset query int false "Number of users to skip (default 0)"
// @Success      200 {object} ListUsersResponse "List of users"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      403 {object} map[string]string "Insufficient scope"
// @Router       /admin/users [get]
func (s *Server) HandleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	// Parse pagination parameters
	limit := 20
	offset := 0

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
			if limit > 100 {
				limit = 100 // Cap at 100
			}
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// Get total count
	total, err := s.datastore.Q.CountUsers(r.Context())
	if err != nil {
		log.Printf("Admin list users: failed to count users: %v", err)
		s.writeAdminError(w, http.StatusInternalServerError, "server_error", "Failed to count users")
		return
	}

	// Get users
	users, err := s.datastore.Q.ListUsers(r.Context(), db.ListUsersParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		log.Printf("Admin list users: failed to list users: %v", err)
		s.writeAdminError(w, http.StatusInternalServerError, "server_error", "Failed to list users")
		return
	}

	// Convert to response format
	userResponses := make([]UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = UserResponse{
			ID:            user.ID.String(),
			Username:      user.Username,
			Email:         user.Email,
			IsActive:      user.IsActive,
			EmailVerified: user.EmailVerified,
			MFAEnabled:    user.MfaEnabled,
			CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:     user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	response := ListUsersResponse{
		Users:   userResponses,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: int64(offset+len(users)) < total,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleAdminGetUser godoc
// @Summary      Get a user by ID (Admin API)
// @Description  Returns a single user by their ID. Requires admin:users:read scope.
// @Tags         admin
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "User ID (UUID)"
// @Success      200 {object} UserResponse "User details"
// @Failure      400 {object} map[string]string "Invalid user ID"
// @Failure      401 {object} map[string]string "Unauthorized"
// @Failure      403 {object} map[string]string "Insufficient scope"
// @Failure      404 {object} map[string]string "User not found"
// @Router       /admin/users/{id} [get]
func (s *Server) HandleAdminGetUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID from URL parameter
	userIDStr := chi.URLParam(r, "id")
	if userIDStr == "" {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request", "User ID is required")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request", "Invalid user ID format")
		return
	}

	// Get user from database (including inactive users for admin API)
	user, err := s.datastore.Q.GetUserByIDIncludingInactive(r.Context(), userID)
	if err == sql.ErrNoRows {
		s.writeAdminError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	if err != nil {
		log.Printf("Admin get user: failed to get user %s: %v", userIDStr, err)
		s.writeAdminError(w, http.StatusInternalServerError, "server_error", "Failed to get user")
		return
	}

	response := UserResponse{
		ID:            user.ID.String(),
		Username:      user.Username,
		Email:         user.Email,
		IsActive:      user.IsActive,
		EmailVerified: user.EmailVerified,
		MFAEnabled:    user.MfaEnabled,
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:     user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
