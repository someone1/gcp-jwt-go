package oauth2

// Based on https://github.com/golang/oauth2/blob/master/google/jwt.go

import (
	"context"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"

	gcp_jwt "github.com/someone1/gcp-jwt-go"
)

// JWTAccessTokenSource returns a TokenSource that uses the IAM API to sign tokens.
// This is meant as a helper for situations in which you want to authenticate calls
// using the configured service account and does not actually perform an Oauth flow.
// This can be useful in service to service communications for user-defined APIs.
// The audience is typically a URL that specifies the scope of the credentials or the
// API endpoint.
//
// Complimentary to https://github.com/someone1/gcp-jwt-go/jwtmiddleware
func JWTAccessTokenSource(ctx context.Context, config *gcp_jwt.IAMSignJWTConfig, audience string) (oauth2.TokenSource, error) {
	ctx = gcp_jwt.NewContextJWT(ctx, config)
	ts := &jwtAccessTokenSource{
		ctx:       ctx,
		audience:  audience,
		jwtConfig: config,
	}
	tok, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return oauth2.ReuseTokenSource(tok, ts), nil
}

type jwtAccessTokenSource struct {
	ctx       context.Context
	audience  string
	jwtConfig *gcp_jwt.IAMSignJWTConfig
}

func (ts *jwtAccessTokenSource) Token() (*oauth2.Token, error) {
	iat := time.Now()
	exp := iat.Add(time.Hour)
	claims := &jwt.StandardClaims{
		Issuer:    ts.jwtConfig.ServiceAccount,
		Subject:   ts.jwtConfig.ServiceAccount,
		IssuedAt:  iat.Unix(),
		NotBefore: iat.Unix(),
		ExpiresAt: exp.Unix(),
		Audience:  ts.audience,
	}

	token := jwt.New(gcp_jwt.SigningMethodGCPJWT)
	token.Claims = claims

	signingString, err := token.SigningString()
	if err != nil {
		return nil, err
	}

	at, err := token.Method.Sign(signingString, ts.ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp_jwt.oauth2: could not sign JWT: %v", err)
	}
	return &oauth2.Token{AccessToken: at, TokenType: "Bearer", Expiry: exp}, nil
}
