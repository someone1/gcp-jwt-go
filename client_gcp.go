// +build !appengine

package gcpjwt

import (
	"context"
	"net/http"
)

func getDefaultClient(ctx context.Context) *http.Client {
	return http.DefaultClient
}
