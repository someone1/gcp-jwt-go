// +build appengine

package gcpjwt

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"

	"google.golang.org/appengine"

	"github.com/dgrijalva/jwt-go"
)

// Implements the built-in AppEngine signing method
// This method uses a private key unique to your AppEngine
// application and the key may rotate from time to time.
// https://cloud.google.com/appengine/docs/go/reference#SignBytes
// https://cloud.google.com/appengine/docs/go/appidentity/#Go_Asserting_identity_to_other_systems
type SigningMethodAppEngineImpl struct{}

type aecertificates []appengine.Certificate

var (
	SigningMethodAppEngine *SigningMethodAppEngineImpl
)

func init() {
	SigningMethodAppEngine = &SigningMethodAppEngineImpl{}
	jwt.RegisterSigningMethod(SigningMethodAppEngine.Alg(), func() jwt.SigningMethod {
		return SigningMethodAppEngine
	})
}

func (s *SigningMethodAppEngineImpl) Alg() string {
	return "AppEngine" // Non-standard!
}

// Implements the Sign method from SigningMethod
// For this signing method, a valid appengine.Context must be
// passed as the key.
func (s *SigningMethodAppEngineImpl) Sign(signingString string, key interface{}) (string, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return "", jwt.ErrInvalidKey
	}

	_, signature, err := appengine.SignBytes(ctx, []byte(signingString))

	if err != nil {
		return "", err
	}

	return jwt.EncodeSegment(signature), nil
}

// Implements the Verify method from SigningMethod
// For this signing method, a valid appengine.Context must be
// passed as the key.
func (s *SigningMethodAppEngineImpl) Verify(signingString, signature string, key interface{}) error {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return jwt.ErrInvalidKey
	}

	var sig []byte
	var err error
	if sig, err = jwt.DecodeSegment(signature); err != nil {
		return err
	}

	var certs aecertificates
	certs, err = appengine.PublicCertificates(ctx)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))

	var certErr error
	for _, cert := range certs {
		rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(cert.Data)
		if err != nil {
			return err
		}

		if certErr = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hasher.Sum(nil), sig); certErr == nil {
			return nil
		}
	}

	return certErr
}
