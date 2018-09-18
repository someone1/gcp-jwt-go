package oauth2

// Based on https://github.com/golang/oauth2/blob/master/google/jwt.go

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"

	"gopkg.in/someone1/gcp-jwt-go.v2"
)

// JWTAccessTokenSource returns a TokenSource that uses the IAM API to sign tokens.
// This is meant as a helper for situations in which you want to authenticate calls
// using the configured service account and does not actually perform an Oauth flow.
// This can be useful in service to service communications for user-defined APIs.
// The audience is typically a URL that specifies the scope of the credentials or the
// API endpoint.
//
// Complimentary to https://gopkg.in/someone1/gcp-jwt-go.v2/jwtmiddleware
func JWTAccessTokenSource(ctx context.Context, config *gcpjwt.IAMConfig, audience string) (oauth2.TokenSource, error) {
	ctx = gcpjwt.NewIAMContext(ctx, config)
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
	jwtConfig *gcpjwt.IAMConfig
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

	var token *jwt.Token
	switch ts.jwtConfig.IAMType {
	case gcpjwt.IAMBlobType:
		token = jwt.New(gcpjwt.SigningMethodIAMBlob)
	case gcpjwt.IAMJwtType:
		token = jwt.New(gcpjwt.SigningMethodIAMJWT)
	default:
		return nil, fmt.Errorf("gcpjwt/oauth2: unknown token type `%v` provided", ts.jwtConfig.IAMType)
	}

	token.Claims = claims

	signingString, err := token.SigningString()
	if err != nil {
		return nil, err
	}

	at, err := token.Method.Sign(signingString, ts.ctx)
	if err != nil {
		return nil, fmt.Errorf("gcpjwt/oauth2: could not sign JWT: %v", err)
	}

	if ts.jwtConfig.IAMType == gcpjwt.IAMBlobType {
		at = strings.Join([]string{signingString, at}, ".")
	}

	return &oauth2.Token{AccessToken: at, TokenType: "Bearer", Expiry: exp}, nil
}
