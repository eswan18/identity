package httpserver

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/eswan18/identity/pkg/cimd"
)

// fakeClientMetadata stands in for *cimd.Resolver in tests: pkg/cimd keeps its
// network seams unexported, so the handlers depend on clientMetadataResolver
// and tests hand them this. It keeps the real resolver's allow-list contract
// (HostAllowed, and ErrHostNotAllowed before any "fetch") and counts the
// fetches it would have made, so a test can assert none happened.
type fakeClientMetadata struct {
	mu      sync.Mutex
	allowed []string
	docs    map[string]*cimd.Metadata
	errs    map[string]error
	fetches map[string]int
}

var _ clientMetadataResolver = (*fakeClientMetadata)(nil)
var _ clientMetadataResolver = (*cimd.Resolver)(nil)

func newFakeClientMetadata(allowedHosts ...string) *fakeClientMetadata {
	return &fakeClientMetadata{
		allowed: allowedHosts,
		docs:    map[string]*cimd.Metadata{},
		errs:    map[string]error{},
		fetches: map[string]int{},
	}
}

func (f *fakeClientMetadata) Enabled() bool { return len(f.allowed) > 0 }

func (f *fakeClientMetadata) HostAllowed(clientID string) bool {
	if !cimd.IsClientIDURL(clientID) {
		return false
	}
	u, err := url.Parse(clientID)
	return err == nil && slices.Contains(f.allowed, u.Host)
}

func (f *fakeClientMetadata) Resolve(_ context.Context, clientID string) (*cimd.Metadata, error) {
	if !f.HostAllowed(clientID) {
		return nil, fmt.Errorf("%w: %s", cimd.ErrHostNotAllowed, clientID)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches[clientID]++
	if err := f.errs[clientID]; err != nil {
		return nil, err
	}
	md, ok := f.docs[clientID]
	if !ok {
		return nil, fmt.Errorf("%w: status 404", cimd.ErrFetch)
	}
	out := *md
	out.RedirectURIs = slices.Clone(md.RedirectURIs)
	return &out, nil
}

// serve makes clientID's document say name and redirectURIs, as if just
// fetched (FetchedAt now, at Postgres precision, as the real resolver sets
// it), and clears any error set for it.
func (f *fakeClientMetadata) serve(clientID, name string, redirectURIs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().Truncate(time.Microsecond)
	f.docs[clientID] = &cimd.Metadata{
		ClientID:     clientID,
		ClientName:   name,
		RedirectURIs: redirectURIs,
		FetchedAt:    now,
		ExpiresAt:    now.Add(cimd.MinCacheTTL),
	}
	delete(f.errs, clientID)
}

// fail makes resolving clientID return err.
func (f *fakeClientMetadata) fail(clientID string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[clientID] = err
}

// fetchCount is how many times clientID got past the allow-list.
func (f *fakeClientMetadata) fetchCount(clientID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches[clientID]
}
