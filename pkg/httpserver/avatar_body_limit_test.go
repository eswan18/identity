package httpserver

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eswan18/identity/pkg/avatar"
)

// newAvatarMultipartRequest builds a POST /oauth/change-avatar request whose
// multipart/form-data body contains an "avatar" file part of exactly fileSize
// bytes plus a csrf_token field, mirroring the shape of a real browser upload
// (see avatar_integration_test.go's TestAvatarUpload for the same construction
// against a live server).
func newAvatarMultipartRequest(t *testing.T, fileSize int) *http.Request {
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("avatar", "test.jpg")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := io.CopyN(part, zeroReader{}, int64(fileSize)); err != nil {
		t.Fatalf("writing %d bytes into avatar part: %v", fileSize, err)
	}
	if err := writer.WriteField("csrf_token", "some-csrf-token-value"); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/change-avatar", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

// zeroReader is an io.Reader that produces an endless stream of zero bytes,
// used so tests can synthesize large multipart file parts without allocating
// a giant byte slice up front.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestMaxAvatarUploadBytes_RejectsOversizedBody is a regression test for the
// avatar-upload DoS gap: without a cap on the raw request body,
// r.ParseMultipartForm's "maxMemory" argument only controls the in-memory vs.
// on-disk split, not the overall amount read, so a client could previously
// POST an effectively unbounded body to /oauth/change-avatar. This verifies
// maxAvatarUploadBytes now stops that at avatar.MaxAvatarRequestBodySize with a
// 413, before the wrapped handler (which would include csrfMiddleware and the
// upload handler itself in the real chain) ever runs.
func TestMaxAvatarUploadBytes_RejectsOversizedBody(t *testing.T) {
	s := newHermeticTestServer(t)
	reached := false
	h := s.maxAvatarUploadBytes(okHandler(&reached))

	// One byte of file content over the hard cap is enough to trip the
	// MaxBytesReader; multipart framing overhead only makes the total larger.
	req := newAvatarMultipartRequest(t, avatar.MaxAvatarRequestBodySize+1)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: expected %d, got %d: %s",
			http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
	}
	if reached {
		t.Fatal("oversized body: next handler must not be reached")
	}
}

// TestMaxAvatarUploadBytes_AllowsLegitimateUpload verifies a realistically
// sized upload (a ~1KB stand-in for a real image, plus the csrf_token field)
// comfortably clears the bound and reaches the wrapped handler, with the
// multipart form already parsed and its fields available.
func TestMaxAvatarUploadBytes_AllowsLegitimateUpload(t *testing.T) {
	s := newHermeticTestServer(t)
	reached := false
	var sawCSRFToken string
	h := s.maxAvatarUploadBytes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		sawCSRFToken = r.FormValue("csrf_token")
		w.WriteHeader(http.StatusOK)
	}))

	req := newAvatarMultipartRequest(t, 1024)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("legitimate upload: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !reached {
		t.Fatal("legitimate upload: next handler must be reached")
	}
	if sawCSRFToken != "some-csrf-token-value" {
		t.Fatalf("legitimate upload: expected csrf_token field to survive parsing, got %q", sawCSRFToken)
	}
}

// TestMaxAvatarUploadBytes_AllowsUpToMaxAvatarSizePlusOverhead is a sanity
// check that a file at the application-level image cap (avatar.MaxAvatarSize)
// still fits under the request-body bound once multipart framing and the
// csrf_token field are added -- i.e. the hard network cap is not tighter than
// the cap the handler itself enforces.
func TestMaxAvatarUploadBytes_AllowsUpToMaxAvatarSizePlusOverhead(t *testing.T) {
	s := newHermeticTestServer(t)
	reached := false
	h := s.maxAvatarUploadBytes(okHandler(&reached))

	req := newAvatarMultipartRequest(t, avatar.MaxAvatarSize)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("MaxAvatarSize upload: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !reached {
		t.Fatal("MaxAvatarSize upload: next handler must be reached")
	}
}

// TestChangeAvatarRoute_OversizedBodyRejectedBeforeCSRF drives the request
// through the real router (registerRoutes) rather than calling the middleware
// directly, confirming the route is wired so the body-size limit applies
// ahead of csrfMiddleware: with no csrf_token cookie at all (which would
// normally trip csrfMiddleware's 403 "missing CSRF token" check first if it
// ran before the size check), an oversized body still gets the 413 from
// maxAvatarUploadBytes, proving that middleware runs first.
func TestChangeAvatarRoute_OversizedBodyRejectedBeforeCSRF(t *testing.T) {
	s := newHermeticTestServer(t)

	req := newAvatarMultipartRequest(t, avatar.MaxAvatarRequestBodySize+1)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 from the body-size limit ahead of CSRF, got %d: %s",
			rec.Code, rec.Body.String())
	}
}
