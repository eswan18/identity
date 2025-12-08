package httpserver

// LoginPageData holds the data needed to render the login page template.
type LoginPageData struct {
	Error               string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
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
