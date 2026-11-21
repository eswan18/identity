// Package assets holds the admin panel's compiled stylesheet, embedded so
// identity-cli stays one self-contained binary.
package assets

import _ "embed"

// StyleCSS is style.css, built from input.css by `make css`.
//
//go:embed style.css
var StyleCSS []byte
