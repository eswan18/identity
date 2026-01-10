package config

import "testing"

const validPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICQMNHONu2Sud2tu6jgOZs3LIj5yOZr89NBMLYiyqBK/oAoGCCqGSM49
AwEHoUQDQgAERCHWHrX20emk31HypGNgptwBjdZOyBybV/9BLTbJPj8UsZ/46ri5
/eFKkRfNApxFU/5lk1RGQJqt8t0GvkkJdw==
-----END EC PRIVATE KEY-----`

func TestValidateECDSAPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{
			name:    "valid key",
			key:     validPrivateKey,
			wantErr: false,
		},
		{
			name:    "invalid PEM",
			key:     "not a valid key",
			wantErr: true,
		},
		{
			name:    "empty key",
			key:     "",
			wantErr: true,
		},
		{
			name: "RSA key instead of ECDSA",
			key: `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALRiMLAHudeSA2ai4S4F5FDTAmmQ
-----END RSA PRIVATE KEY-----`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateECDSAPrivateKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateECDSAPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIssuerURL(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		wantErr bool
	}{
		{
			name:    "valid https URL",
			issuer:  "https://identity.example.com",
			wantErr: false,
		},
		{
			name:    "valid http URL",
			issuer:  "http://localhost:8080",
			wantErr: false,
		},
		{
			name:    "https with path",
			issuer:  "https://example.com/auth",
			wantErr: false,
		},
		{
			name:    "missing scheme",
			issuer:  "identity.example.com",
			wantErr: true,
		},
		{
			name:    "invalid scheme",
			issuer:  "ftp://identity.example.com",
			wantErr: true,
		},
		{
			name:    "empty string",
			issuer:  "",
			wantErr: true,
		},
		{
			name:    "scheme only",
			issuer:  "https://",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIssuerURL(tt.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIssuerURL(%q) error = %v, wantErr %v", tt.issuer, err, tt.wantErr)
			}
		})
	}
}
