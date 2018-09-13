// +build appengine

package gcpjwt

import (
	"net/http"

	"golang.org/x/net/context"
	"google.golang.org/appengine/urlfetch"
)

func getDefaultClient(ctx context.Context) *http.Client {
	return urlfetch.Client(ctx)
}
