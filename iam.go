package gcpjwt

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/api/iam/v1"
)

type signingMethodIAM struct {
	alg  string
	sign func(ctx context.Context, iamService *iam.Service, config *IAMConfig, signingString string) (string, error)
}

func (s *signingMethodIAM) Alg() string {
	return s.alg
}

// Sign implements the Sign method from jwt.SigningMethod
// For this signing method, a valid context.Context must be
// passed as the key containing a IAMConfig value
// NOTE: The HEADER IS IGNORED for the signJWT API as the API will add its own
func (s *signingMethodIAM) Sign(signingString string, key interface{}) (string, error) {
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
	iamService, err := iam.New(client)
	if err != nil {
		return "", err
	}

	return s.sign(ctx, iamService, config, signingString)
}

// IAMVerfiyKeyfunc is a helper meant that returns a jwt.Keyfunc. It will handle pulling and selecting the certificates
// to verify signatures with, caching when enabled.
func IAMVerfiyKeyfunc(ctx context.Context, config *IAMConfig) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Make sure we have the proper header alg
		if _, ok := token.Method.(*signingMethodIAM); !ok {
			return nil, fmt.Errorf("gcpjwt: unexpected signing method: %v", token.Header["alg"])
		}

		// Default config.Client is a http.DefaultClient
		client := config.Client
		if client == nil {
			client = getDefaultClient(ctx)
		}

		// Get the certificates
		var certs certificates
		if !config.EnableCache {
			// Not leveraging the cache, do a HTTP request for the certificates and carry on
			certResp, cerr := getCertificatesForAccount(client, config.ServiceAccount)
			if cerr != nil {
				return nil, cerr
			}
			certs = certResp.certs
		} else {
			if certsResp, ok := getCertsFromCache(config.ServiceAccount); ok {
				certs = certsResp
			} else {
				// Nothing in cache, let's hydrate
				certResp, cerr := getCertificatesForAccount(client, config.ServiceAccount)
				if cerr != nil {
					return nil, cerr
				}
				updateCache(config.ServiceAccount, certResp.certs, certResp.expires)
				certs = certResp.certs
			}
		}

		var certList []*rsa.PublicKey
		kid, ok := token.Header["kid"].(string)
		if ok && kid != "" {
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

// Verify implements the Verify method from jwt.SigningMethod
// This will expect key type of []*rsa.PublicKey.
// https://firebase.google.com/docs/auth/admin/verify-id-tokens
func (s *signingMethodIAM) Verify(signingString, signature string, key interface{}) error {
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
