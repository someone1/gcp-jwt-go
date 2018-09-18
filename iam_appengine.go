// +build appengine

package gcpjwt

import (
	"context"
	"time"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/appengine"
)

const appEngineSvcAcct = "APPENGINE"

// SigningMethodAppEngineImpl implements singing JWT's using the built-in AppEngine signing method. This method uses a
// private key unique to your AppEngine application and the key may rotate from time to time.
// https://cloud.google.com/appengine/docs/go/reference#SignBytes
// https://cloud.google.com/appengine/docs/go/appidentity/#Go_Asserting_identity_to_other_systems
type SigningMethodAppEngineImpl struct {
	*SigningMethodIAM

	lastKeyID string
}

var (
	SigningMethodAppEngine *SigningMethodAppEngineImpl
)

func init() {
	SigningMethodAppEngine = &SigningMethodAppEngineImpl{
		SigningMethodIAM: &SigningMethodIAM{
			alg:      "AppEngine",
			override: jwt.SigningMethodRS256.Alg(),
			sign:     nil,
		},
	}
	jwt.RegisterSigningMethod(SigningMethodAppEngine.Alg(), func() jwt.SigningMethod {
		return SigningMethodAppEngine
	})
}

// Sign implements the Sign method from jwt.SigningMethod. For this signing method, a valid AppEngine context.Context
// must be passed as the key.
func (s *SigningMethodAppEngineImpl) Sign(signingString string, key interface{}) (string, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return "", jwt.ErrInvalidKey
	}

	keyName, signature, err := appengine.SignBytes(ctx, []byte(signingString))
	if err != nil {
		return "", err
	}

	s.lastKeyID = keyName

	return jwt.EncodeSegment(signature), nil
}

// KeyID will return the last used KeyID to sign the JWT.
// Helper function for adding the kid header to your token.
func (s *SigningMethodAppEngineImpl) KeyID() string {
	return s.lastKeyID
}

var (
	appEngineKeyfunc = &keyFuncHelper{
		compareMethod: func(j jwt.SigningMethod) bool {
			_, ok := j.(*SigningMethodAppEngineImpl)
			return ok
		},
		certificates: getAppEngineCertificates,
	}
)

// AppEngineVerfiyKeyfunc is a helper meant that returns a jwt.Keyfunc. It will handle pulling and selecting the
// certificates to verify signatures with, caching when enabled.
func AppEngineVerfiyKeyfunc(ctx context.Context, enableCache bool, cacheExpiration time.Duration) jwt.Keyfunc {
	config := &IAMConfig{
		EnableCache:     enableCache,
		CacheExpiration: cacheExpiration,
	}
	return appEngineKeyfunc.verifyKeyfunc(ctx, config)
}

func getAppEngineCertificates(ctx context.Context, config *IAMConfig) (certificates, error) {
	if config.EnableCache {
		if certsResp, ok := getCertsFromCache(appEngineSvcAcct); ok {
			return certsResp, nil
		}
	}

	aeCerts, err := appengine.PublicCertificates(ctx)
	if err != nil {
		return nil, err
	}

	certs := make(certificates)
	for _, cert := range aeCerts {
		rsaKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Data))
		if err != nil {
			return nil, err
		}
		certs[cert.KeyName] = rsaKey
	}

	if config.EnableCache {
		updateCache(appEngineSvcAcct, certs, time.Now().Add(config.CacheExpiration))
	}

	return certs, nil
}
