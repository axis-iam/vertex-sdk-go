package iamchi

import (
	"net/http"

	"github.com/axis-iam/vertex-sdk-go/websession"
)

// WebSessionHandler mounts the shared C0 routes without stripping BasePath.
func WebSessionHandler(service *websession.Service) http.Handler { return service.Handler() }

// WebSession protects an explicitly selected business route using Cookie auth.
func WebSession(service *websession.Service) func(http.Handler) http.Handler {
	return service.Middleware
}
