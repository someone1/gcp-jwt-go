// +build appengine

package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	gcp_jwt "github.com/someone1/gcp-jwt-go"
	"google.golang.org/appengine"
)

// NewHandler will return a middleware that will try and validate tokens in incoming HTTP requests.
// The token is expected as a Bearer token in the Authorization header and expected to have an Issuer
// claim equal to the ServiceAccount the provided IAMSignJWTConfig is configured for. This will also validate the
// Audience claim to the one provided, or use https:// + request.Host if blank.
//
// Complimentary to https://github.com/someone1/gcp-jwt-go/oauth2
func NewHandler(_ context.Context, config *gcp_jwt.IAMSignJWTConfig, audience string) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := gcp_jwt.NewContextJWT(appengine.NewContext(r), config)

			keyFunc := func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*gcp_jwt.SigningMethodGCPJWTImpl); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
				}
				return ctx, nil
			}
			claims := &jwt.StandardClaims{}

			token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, keyFunc, request.WithClaims(claims))
			if err != nil || !token.Valid {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}

			aud := audience
			if aud == "" {
				aud = fmt.Sprintf("https://%s", r.Host)
			}

			if !claims.VerifyAudience(aud, true) || !claims.VerifyIssuer(config.ServiceAccount, true) {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}

			h.ServeHTTP(w, r)
		})
	}
}
