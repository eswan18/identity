package cmd

import (
	"strings"

	"github.com/eswan18/identity/pkg/db"
)

// A registered client's resource allow-list: the resources it may request by
// name with the resource parameter, beyond its default resource (which is
// always allowed). client create --resources sets it; client update
// --resources replaces it, --add-resources and --remove-resources edit it,
// with the same semantics as the redirect-URI flags.

// allowedResourcesValue renders a client's allow-list for display.
func allowedResourcesValue(resources []db.OauthResource) string {
	if len(resources) == 0 {
		return "(none beyond the default)"
	}
	uris := make([]string, len(resources))
	for i, r := range resources {
		uris[i] = r.Uri
	}
	return strings.Join(uris, ", ")
}
