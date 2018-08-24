package gcp_jwt

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

var (
	// SigningMethodGCP implements signing JWTs with
	// the IAM signBlob API
	SigningMethodGCP *SigningMethodGCPImpl
)

type gcpConfigKey struct{}

// IAMSignBlobConfig holds config relevant to
// interfacing with the API
type IAMSignBlobConfig struct {
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

// SigningMethodGCPImpl implements the GCP IAM sign blob method
// This method uses a private key unique to your IAM account
// and the key may rotate from time to time.
// https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signBlob
// https://firebase.google.com/docs/auth/admin/verify-id-tokens
type SigningMethodGCPImpl struct{}

func init() {
	SigningMethodGCP = &SigningMethodGCPImpl{}
	jwt.RegisterSigningMethod(SigningMethodGCP.Alg(), func() jwt.SigningMethod {
		return SigningMethodGCP
	})
}

func (s *SigningMethodGCPImpl) Alg() string {
	return "GCP" // Non-standard!
}

// Implements the Sign method from SigningMethod
// For this signing method, a valid context.Context must be
// passed as the key containing a GCPConfig value
func (s *SigningMethodGCPImpl) Sign(signingString string, key interface{}) (string, error) {
	var ctx context.Context

	// check to make sure the key is a context.Context
	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return "", jwt.ErrInvalidKey
	}

	// Get the IAMSignBlobConfig from the context
	config, ok := FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("GCPConfig missing from provided context!")
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
	signReq := &iam.SignBlobRequest{
		BytesToSign: base64.StdEncoding.EncodeToString([]byte(signingString)),
	}
	name := fmt.Sprintf("projects/%s/serviceAccounts/%s", config.ProjectID, config.ServiceAccount)

	// Do the call
	iamService, err := iam.New(config.OAuth2HTTPClient)
	if err != nil {
		return "", err
	}

	signResp, err := iamService.Projects.ServiceAccounts.SignBlob(name, signReq).Do()
	if err != nil {
		return "", err
	}

	// Check the response
	if signResp.HTTPStatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected response code from signing request, expected %d but got %d instead", http.StatusOK, signResp.HTTPStatusCode)
	}

	signature, err := base64.StdEncoding.DecodeString(signResp.Signature)
	if err != nil {
		return "", err
	}

	return jwt.EncodeSegment(signature), nil
}

// Implements the Verify method from SigningMethod
// For this signing method, a valid context.Context must be
// passed as the key containing a GCPConfig value
func (s *SigningMethodGCPImpl) Verify(signingString, signature string, key interface{}) error {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return jwt.ErrInvalidKey
	}

	// Get the IAMSignBlobConfig from the context
	config, ok := FromContext(ctx)
	if !ok {
		return fmt.Errorf("GCPConfig missing from provided context!")
	}

	// Default config.Client is a http.DefaultClient
	client := config.Client
	if client == nil {
		client = getDefaultClient(ctx)
	}

	var sig []byte
	var err error
	if sig, err = jwt.DecodeSegment(signature); err != nil {
		return err
	}

	var certs certificates

	if config.DisableCache {
		// Not leveraging the cache, do a HTTP request for the certificates and carry on
		certResp, err := getCertificatesForAccount(client, config.ServiceAccount)
		if err != nil {
			return err
		}
		certs = certResp.certs
	} else {
		// Check the cache for the certs and use those, otherwise grab 'em
		if c, ok := getCertsFromCache(config.ServiceAccount); ok {
			certs = c
		} else {
			certResponse, err := getCertificatesForAccount(client, config.ServiceAccount)
			if err != nil {
				return err
			}
			certs = certResponse.certs
			updateCache(config.ServiceAccount, certs, certResponse.expires)
		}
	}

	hasher := sha256.New()
	_, err = hasher.Write([]byte(signingString))
	if err != nil {
		return err
	}
	hash := hasher.Sum(nil)

	// TODO:
	// If the certs can rotate before the cache expires, what should we do?
	// Do we invalidate the cache if we cannot authenticate or would that
	// enable a DDoS-like attack where every request fails the cache and
	// the program keeps trying to fetch replacements. For now, do nothing.

	return verifyWithCerts(sig, hash, certs)
}

// NewContext returns a new context.Context that carries a provided IAMSignBlobConfig value
func NewContext(parent context.Context, val *IAMSignBlobConfig) context.Context {
	return context.WithValue(parent, gcpConfigKey{}, val)
}

// FromContext extracts a IAMSignBlobConfig from a context.Context
func FromContext(ctx context.Context) (*IAMSignBlobConfig, bool) {
	val, ok := ctx.Value(gcpConfigKey{}).(*IAMSignBlobConfig)
	return val, ok
}

func getDefaultOauthClient(ctx context.Context) (*http.Client, error) {
	return google.DefaultClient(ctx, iam.CloudPlatformScope)
}
