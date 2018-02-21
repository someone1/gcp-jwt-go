package gcp_jwt

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context"
	"google.golang.org/api/iam/v1"
)

var (
	// SigningMethodGCPJWT implements signing JWTs with
	// the IAM signJwt API
	SigningMethodGCPJWT *SigningMethodGCPJWTImpl
)

type gcpJwtConfigKey struct{}

// IAMSignJWTConfig holds config relevant to
// interfacing with the API
type IAMSignJWTConfig struct {
	// Service account can be the email address or the uniqueId of the service account used to sign the JWT with
	ServiceAccount string

	// Project ID is the project id that contains the service account you want to sign with. Defaults to "-" to infer the project from the account
	ProjectID string

	// User provided oauth2 authenticated http.Client to use, google.DefaultClient used otherwise
	// Used for signing requests
	OAuth2HTTPClient *http.Client

	// User provided http.Client to use, http.DefaultClient used otherwise
	// Used for verify requests
	Client *http.Client

	// Disable cache will disable the in-memory caching of public certificates based on service account.
	// The cache is "dumb" in that it will never expire its contents and will refresh the cache if
	// it is unable to verify a signature from any of the certificates provided. Should be ok to use
	// for applications with few service accounts used to sign with.
	DisableCache bool
}

// SigningMethodGCPJWTImpl implements the GCP IAM sign JWT method
// This method uses a private key unique to your service account
// and the key may rotate from time to time.
// https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signJwt
// https://firebase.google.com/docs/auth/admin/verify-id-tokens
type SigningMethodGCPJWTImpl struct{}

type gcpJwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

func init() {
	SigningMethodGCPJWT = &SigningMethodGCPJWTImpl{}
	jwt.RegisterSigningMethod(SigningMethodGCPJWT.Alg(), func() jwt.SigningMethod {
		return SigningMethodGCPJWT
	})
}

// OverrisdeRS256 will replace the original RS256 method with this for more seamless use
func OverrideRS256() {
	jwt.RegisterSigningMethod(jwt.SigningMethodRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodGCPJWT
	})
}

func (s *SigningMethodGCPJWTImpl) Alg() string {
	return "GCPJWT" // This is NOT used
}

// Implements the Sign method from SigningMethod
// For this signing method, a valid context.Context must be
// passed as the key containing a IAMSignJWTConfig value
// NOTE: The HEADER IS IGNORED as the API will add its own
func (s *SigningMethodGCPJWTImpl) Sign(signingString string, key interface{}) (string, error) {
	var ctx context.Context

	// check to make sure the key is a context.Context
	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return "", jwt.ErrInvalidKey
	}

	// Get the IAMSignBlobConfig from the context
	config, ok := FromContextJWT(ctx)
	if !ok {
		return "", fmt.Errorf("IAMSignJWTConfig missing from provided context!")
	}

	// Default config.OAuth2HTTPClient is a google.DefaultClient
	if config.OAuth2HTTPClient == nil {
		c, err := getDefaultOauthClient(ctx)
		if err != nil {
			return "", err
		}
		config.OAuth2HTTPClient = c
	}

	// Default the ProjectID to a wildcard
	if config.ProjectID == "" {
		config.ProjectID = "-"
	}

	// Prepare the call
	// First decode the JSON string and discard the header
	parts := strings.Split(signingString, ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("expected a 2 part string to sign, but got %d instead", len(parts))
	}
	jwtClaimSet, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		return "", err
	}

	signReq := &iam.SignJwtRequest{Payload: string(jwtClaimSet)}
	name := fmt.Sprintf("projects/%s/serviceAccounts/%s", config.ProjectID, config.ServiceAccount)

	// Do the call
	iamService, err := iam.New(config.OAuth2HTTPClient)
	if err != nil {
		return "", err
	}

	signResp, err := iamService.Projects.ServiceAccounts.SignJwt(name, signReq).Do()
	if err != nil {
		return "", err
	}

	// Check the response
	if signResp.HTTPStatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected response code from signing request, expected %d but got %d instead", http.StatusOK, signResp.HTTPStatusCode)
	}

	return signResp.SignedJwt, nil
}

// Implements the Verify method from SigningMethod
// For this signing method, a valid context.Context must be
// passed as the key containing a IAMSignJWTConfig value
func (s *SigningMethodGCPJWTImpl) Verify(signingString, signature string, key interface{}) error {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return jwt.ErrInvalidKey
	}

	// Get the IAMSignBlobConfig from the context
	config, ok := FromContextJWT(ctx)
	if !ok {
		return fmt.Errorf("IAMSignJWTConfig missing from provided context!")
	}

	// Default config.Client is a http.DefaultClient
	if config.Client == nil {
		config.Client = getDefaultClient(ctx)
	}

	// Let's get the header
	parts := strings.Split(signingString, ".")
	if len(parts) != 2 {
		return fmt.Errorf("expected a 2 part string to sign, but got %d instead", len(parts))
	}
	jwtHeaderRaw, err := jwt.DecodeSegment(parts[0])
	if err != nil {
		return err
	}
	header := &gcpJwtHeader{}
	err = json.Unmarshal(jwtHeaderRaw, header)
	if err != nil {
		return err
	}

	// Validate the algorithm and get the KeyID
	if header.Algorithm != jwt.SigningMethodRS256.Alg() {
		return fmt.Errorf("expected alg RS256, got %s instead", header.Algorithm)
	}

	var sig []byte
	if sig, err = jwt.DecodeSegment(signature); err != nil {
		return err
	}

	var cert string

	if config.DisableCache {
		// Not leveraging the cache, do a HTTP request for the certificates and carry on
		certResp, cerr := getCertificatesForAccount(config.Client, config.ServiceAccount)
		if cerr != nil {
			return cerr
		}
		if c, ok := certResp.certs[header.KeyID]; ok {
			cert = c
		} else {
			return fmt.Errorf("could not find certificate associated with kid %s for serviceaccount %s", header.KeyID, config.ServiceAccount)
		}
	} else {
		// Check the cache for the certs and use those, otherwise grab 'em
		if c, ok := getCertFromCache(config.ServiceAccount, header.KeyID); ok {
			cert = c
		} else {
			certResp, cerr := getCertificatesForAccount(config.Client, config.ServiceAccount)
			if cerr != nil {
				return cerr
			}
			if c, ok := certResp.certs[header.KeyID]; ok {
				cert = c
			} else {
				return fmt.Errorf("could not find certificate associated with kid %s for serviceaccount %s", header.KeyID, config.ServiceAccount)
			}
			updateCache(config.ServiceAccount, certResp.certs, certResp.expires)
		}
	}

	hasher := sha256.New()
	_, err = hasher.Write([]byte(signingString))
	if err != nil {
		return err
	}
	hash := hasher.Sum(nil)

	return verifyWithCert(sig, hash, cert)
}

// NewContextJWT returns a new context.Context that carries a provided IAMSignJWTConfig value
func NewContextJWT(parent context.Context, val *IAMSignJWTConfig) context.Context {
	return context.WithValue(parent, gcpJwtConfigKey{}, val)
}

// FromContextJWT extracts a IAMSignBlobConfig from a context.Context
func FromContextJWT(ctx context.Context) (*IAMSignJWTConfig, bool) {
	val, ok := ctx.Value(gcpJwtConfigKey{}).(*IAMSignJWTConfig)
	return val, ok
}
