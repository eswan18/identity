package httpserver

// LoginPageData holds the data needed to render the login page template.
type LoginPageData struct {
	Error               string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               []string
	CodeChallenge       string
	CodeChallengeMethod string
}

// RegisterPageData holds the data needed to render the registration page template.
type RegisterPageData struct {
	Error               string
	Username            string
	Email               string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               []string
	CodeChallenge       string
	CodeChallengeMethod string
}

// ErrorPageData holds the data needed to render the error page template.
type ErrorPageData struct {
	Title       string
	Message     string
	Details     string
	ErrorCode   string
	RedirectURI string
}

// AccountSettingsPageData holds the data needed to render the account settings page template.
type AccountSettingsPageData struct {
	Error      string
	Success    string
	Username   string
	Email      string
	IsInactive bool
	MfaEnabled bool
}

// ChangePasswordPageData holds the data needed to render the change password page template.
type ChangePasswordPageData struct {
	Error   string
	Success string
}

// ChangeUsernamePageData holds the data needed to render the change username page template.
type ChangeUsernamePageData struct {
	Error           string
	Success         string
	CurrentUsername string
}

// ChangeEmailPageData holds the data needed to render the change email page template.
type ChangeEmailPageData struct {
	Error        string
	Success      string
	CurrentEmail string
}
