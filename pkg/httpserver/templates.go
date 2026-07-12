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
	Nonce               string
	CSRFToken           string
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
	CSRFToken           string
}

// ScopeDescription maps a scope string to a human-readable description.
type ScopeDescription struct {
	Scope       string
	Description string
}

// ConsentPageData holds the data needed to render the consent page template.
type ConsentPageData struct {
	Error               string
	ClientName          string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               []string
	ScopeDescriptions   []ScopeDescription
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	ResponseType        string
	CSRFToken           string
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
	Error         string
	Success       string
	Username      string
	Email         string
	Name          string
	AvatarURL     string
	IsInactive    bool
	MfaEnabled    bool
	EmailVerified bool
	CSRFToken     string
}

// ChangeAvatarPageData holds the data needed to render the change avatar page template.
type ChangeAvatarPageData struct {
	Error     string
	Success   string
	AvatarURL string
	CSRFToken string
}
