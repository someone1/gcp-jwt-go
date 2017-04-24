package gcp_jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
)

const (
	certificateURL = "https://www.googleapis.com/robot/v1/metadata/x509/"
)

var (
	certsCache map[string]certificates
	certMutex  sync.RWMutex

	SigningMethodGCP *SigningMethodGCPImpl
)

type gcpConfigKey struct{}

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

// Implements the GCP IAM signing method
// This method uses a private key unique to your IAM account
// and the key may rotate from time to time.
// https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signBlob
// https://firebase.google.com/docs/auth/admin/verify-id-tokens
type SigningMethodGCPImpl struct{}

type certificates map[string]string

func init() {
	SigningMethodGCP = &SigningMethodGCPImpl{}
	jwt.RegisterSigningMethod(SigningMethodGCP.Alg(), func() jwt.SigningMethod {
		return SigningMethodGCP
	})

	certsCache = make(map[string]certificates)
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
	if config.Client == nil {
		config.Client = getDefaultClient(ctx)
	}

	var sig []byte
	var err error
	if sig, err = jwt.DecodeSegment(signature); err != nil {
		return err
	}

	var certs certificates

	if config.DisableCache {
		// Not leveraging the cache, do a HTTP request for the certificates and carry on
		certs, err = getCertificatesForAccount(config.Client, config.ServiceAccount)
		if err != nil {
			return err
		}
	} else {
		// Check the cache for the certs and use those, otherwise grab 'em
		certMutex.RLock()
		if c, ok := certsCache[config.ServiceAccount]; ok {
			certs = c
			certMutex.RUnlock()
		} else {
			certMutex.RUnlock()
			certs, err = getCertificatesForAccount(config.Client, config.ServiceAccount)
			if err != nil {
				return err
			}
			certMutex.Lock()
			certsCache[config.ServiceAccount] = certs
			certMutex.Unlock()
		}
	}

	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	hash := hasher.Sum(nil)
	err = verifyWithCerts(sig, hash, certs)

	// If we were using a cached version, grab the new certs and try again
	if err != nil && !config.DisableCache {
		certs, err = getCertificatesForAccount(config.Client, config.ServiceAccount)
		if err != nil {
			return err
		}
		certMutex.Lock()
		certsCache[config.ServiceAccount] = certs
		certMutex.Unlock()

		err = verifyWithCerts(sig, hash, certs)
	}

	return err
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

func getCertificatesForAccount(hc *http.Client, account string) (certificates, error) {
	resp, err := hc.Get(certificateURL + account)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	certs := make(certificates)

	err = json.Unmarshal(b, &certs)
	return certs, err
}

func verifyWithCerts(sig, hash []byte, certs certificates) error {
	var certErr error
	for _, cert := range certs {
		rsaKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		if err != nil {
			return err
		}

		if certErr = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash, sig); certErr == nil {
			return nil
		}
	}

	return certErr
}
