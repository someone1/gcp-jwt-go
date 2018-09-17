// +build appengine

package gcpjwt

import (
	"context"
	"net/http"

	"google.golang.org/appengine/urlfetch"
)

func getDefaultClient(ctx context.Context) *http.Client {
	return urlfetch.Client(ctx)
}
