package gcpjwt

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/api/iamcredentials/v1"
)

// SigningMethodIAM is the base implementation for the signBlob and signJwt IAM API JWT signing methods. Not to be used on
// its own!
type SigningMethodIAM struct {
	alg      string
	override string
	sign     func(ctx context.Context, iamService *iamcredentials.Service, config *IAMConfig, signingString string) (string, error)
}

// Alg will return the JWT header algorithm identifier this method is configured for.
func (s *SigningMethodIAM) Alg() string {
	return s.alg
}

// Override will override the default JWT implementation of the signing function this IAM API type implements.
func (s *SigningMethodIAM) Override() {
	s.alg = s.override
	jwt.RegisterSigningMethod(s.override, func() jwt.SigningMethod {
		return s
	})
}

// Sign implements the Sign method from jwt.SigningMethod. For this signing method, a valid context.Context must be
// passed as the key containing a IAMConfig value.
// NOTE: The HEADER IS IGNORED for the signJWT API as the API will add its own
func (s *SigningMethodIAM) Sign(signingString string, key interface{}) (string, error) {
	var ctx context.Context

	// check to make sure the key is a context.Context
	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return "", jwt.ErrInvalidKey
	}

	// Get the IAMConfig from the context
	config, ok := IAMFromContext(ctx)
	if !ok {
		return "", ErrMissingConfig
	}

	// Default config.OAuth2HTTPClient is a google.DefaultClient
	client := config.OAuth2HTTPClient
	if client == nil {
		c, err := getDefaultOauthClient(ctx)
		if err != nil {
			return "", err
		}
		client = c
	}

	// Default the ProjectID to a wildcard
	if config.ProjectID == "" {
		config.ProjectID = "-"
	}

	// Do the call
	iamService, err := iamcredentials.New(client)
	if err != nil {
		return "", err
	}

	return s.sign(ctx, iamService, config, signingString)
}

type keyFuncHelper struct {
	compareMethod func(j jwt.SigningMethod) bool
	certificates  func(ctx context.Context, config *IAMConfig) (certificates, error)
}

var (
	iamKeyfunc = &keyFuncHelper{
		compareMethod: func(j jwt.SigningMethod) bool {
			_, ok := j.(*SigningMethodIAM)
			return ok
		},
		certificates: getCertificates,
	}
)

func (k *keyFuncHelper) verifyKeyfunc(ctx context.Context, config *IAMConfig) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Make sure we have the proper header alg
		if !k.compareMethod(token.Method) {
			return nil, fmt.Errorf("gcpjwt: unexpected signing method: %v", token.Header["alg"])
		}
		certs, err := k.certificates(ctx, config)
		if err != nil {
			return nil, fmt.Errorf("gcpjwt: could not get certificates: %v", err)
		}
		var certList []*rsa.PublicKey
		kid, ok := token.Header["kid"].(string)
		if ok {
			if cert, ok := certs[kid]; ok {
				certList = append(certList, cert)
			}
		} else {
			for _, cert := range certs {
				certList = append(certList, cert)
			}
		}

		if len(certList) == 0 {
			return nil, fmt.Errorf("gcpjwt: could not find certificate(s) for service account `%s` and key id `%s`", config.ServiceAccount, kid)
		}

		return certList, nil
	}
}

// IAMVerfiyKeyfunc is a helper meant that returns a jwt.Keyfunc. It will handle pulling and selecting the certificates
// to verify signatures with, caching when enabled.
func IAMVerfiyKeyfunc(ctx context.Context, config *IAMConfig) jwt.Keyfunc {
	return iamKeyfunc.verifyKeyfunc(ctx, config)
}

// Verify implements the Verify method from jwt.SigningMethod. This will expect key type of []*rsa.PublicKey.
// https://firebase.google.com/docs/auth/admin/verify-id-tokens
func (s *SigningMethodIAM) Verify(signingString, signature string, key interface{}) error {
	rsaKeys, ok := key.([]*rsa.PublicKey)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	var err error
	for _, rsaKey := range rsaKeys {
		err = jwt.SigningMethodRS256.Verify(signingString, signature, rsaKey)
		if err == nil {
			break
		}
	}

	// TODO:
	// If the certs can rotate before the cache expires, what should we do?
	// Do we invalidate the cache if we cannot authenticate or would that
	// enable a DDoS-like attack where every request fails the cache and
	// the program keeps trying to fetch replacements. For now, do nothing.

	return err
}
