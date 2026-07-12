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
