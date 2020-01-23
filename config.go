package gcpjwt

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	iamcredentials "google.golang.org/api/iamcredentials/v1"
)

type iamType int

const (
	// IAMBlobType is used as a hint in the config to let various parts of the library know you intend to use the
	// signBlob IAM API.
	IAMBlobType iamType = iota + 1
	// IAMJwtType is used as a hint in the config to let various parts of the library know you intend to use the
	// signJwt IAM API.
	IAMJwtType
)

var (
	// ErrMissingConfig is returned when Sign or Verify did not find a configuration in the provided context
	ErrMissingConfig = errors.New("gcpjwt: missing configuration in provided context")
)

type iamConfigKey struct{}
type kmsConfigKey struct{}

// IAMConfig is relevant for both the signBlob and signJWT IAM API use-cases
type IAMConfig struct {
	// ProjectID is the project id that contains the service account you want to sign with. Defaults to "-" to infer the project from the account
	// Depcrecated: This field is no longer used as the API will reject all values other than "-".
	ProjectID string

	// Service account can be the email address or the uniqueId of the service account used to sign the JWT with
	ServiceAccount string

	// EnableCache will enable the in-memory caching of public certificates.
	// The cache will expire certificates when an expiration is known or fallback to the configured CacheExpiration
	EnableCache bool

	// CacheExpiration is the default time to keep the certificates in cache if no expiration time is provided
	// Use a value of 0 to disable the expiration time fallback. Max reccomneded value is 24 hours.
	// https://cloud.google.com/iam/docs/understanding-service-accounts#managing_service_account_keys
	CacheExpiration time.Duration

	// IAMType is a helper used to help clarify which IAM signing method this config is meant for.
	// Used for the jwtmiddleware and oauth2 packages.
	IAMType iamType

	// IAMService is a user provided service client that should be used when communicating with the iamcredentials API,
	// otherwuse the default service will be used.
	IAMService *iamcredentials.Service

	// OAuth2HTTPClient is a user provided oauth2 authenticated *http.Client to use, google.DefaultClient used otherwise
	// Used for signing requests
	// Depcrecated: This field is no longer used. Use IAMClient instead
	OAuth2HTTPClient *http.Client

	// Client is a user provided *http.Client to use, http.DefaultClient is used otherwise (AppEngine URL Fetch Supported)
	// Used for verify requests
	Client *http.Client

	lastKeyID string

	sync.RWMutex
}

// KeyID will return the last used KeyID to sign the JWT - though it should be noted the signJwt method will always
// add its own token header which is not parsed back to the token.
// Helper function for adding the kid header to your token.
func (i *IAMConfig) KeyID() string {
	i.RLock()
	defer i.RUnlock()

	return i.lastKeyID
}

// KMSConfig is used to sign/verify JWTs with Google Cloud KMS
type KMSConfig struct {
	// KeyPath is the name of the key to use in the format of:
	// "name=projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*"
	KeyPath string

	// KMSClient to use for calls to the API. If nil, a standard one will be initiated
	KMSClient *kms.KeyManagementClient
}

// KeyID will return the SHA1 hash of the configured KeyPath. Helper function for adding the kid header to your token.
func (k *KMSConfig) KeyID() string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(k.KeyPath)))
}

// NewIAMContext returns a new context.Context that carries a provided IAMConfig value
func NewIAMContext(parent context.Context, val *IAMConfig) context.Context {
	return context.WithValue(parent, iamConfigKey{}, val)
}

// IAMFromContext extracts a IAMConfig from a context.Context
func IAMFromContext(ctx context.Context) (*IAMConfig, bool) {
	val, ok := ctx.Value(iamConfigKey{}).(*IAMConfig)
	return val, ok
}

// NewKMSContext returns a new context.Context that carries a provided KMSConfig value
func NewKMSContext(parent context.Context, val *KMSConfig) context.Context {
	return context.WithValue(parent, kmsConfigKey{}, val)
}

// KMSFromContext extracts a KMSConfig from a context.Context
func KMSFromContext(ctx context.Context) (*KMSConfig, bool) {
	val, ok := ctx.Value(kmsConfigKey{}).(*KMSConfig)
	return val, ok
}

func getDefaultClient(ctx context.Context) *http.Client {
	return http.DefaultClient
}
