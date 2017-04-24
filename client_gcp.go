// +build !appengine,!appenginevm

package gcp_jwt

import (
	"net/http"

	"golang.org/x/net/context"
)

func getDefaultClient(ctx context.Context) *http.Client {
	return http.DefaultClient
}
