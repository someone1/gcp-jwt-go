package gcpjwt

import (
	"context"
	"errors"
	"net/http"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
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

// gcpConfig common config elements between signing methods - not to be used on its own
type gcpConfig struct {
	// ProjectID is the project id that contains the service account you want to sign with. Defaults to "-" to infer the project from the account
	ProjectID string

	// OAuth2HTTPClient is a user provided oauth2 authenticated *http.Client to use, google.DefaultClient used otherwise
	// Used for signing requests
	OAuth2HTTPClient *http.Client

	// Client is a user provided *http.Client to use, http.DefaultClient is used otherwise (AppEngine URL Fetch Supported)
	// Used for verify requests
	Client *http.Client

	// EnableCache will enable the in-memory caching of public certificates.
	// The cache will expire certificates when an expiration is known or provided and will refresh the cache if
	// it is unable to verify a signature from any of the certificates cached.
	EnableCache bool

	// InjectKeyID will overwrite the provided header with one that contains the Key ID of the key used to sign the JWT.
	// Note that the IAM JWT signing method does this on its own and this is only applicable for the IAM Blob and Cloud KMS
	// signing methods.
	InjectKeyID bool
}

// IAMConfig is relevant for both the signBlob and signJWT IAM API use-cases
type IAMConfig struct {
	// Service account can be the email address or the uniqueId of the service account used to sign the JWT with
	ServiceAccount string

	// IAMType is a helper used to help clarify which IAM signing method this config is meant for.
	// Used for the jwtmiddleware and oauth2 packages.
	IAMType iamType

	gcpConfig
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

func getDefaultOauthClient(ctx context.Context) (*http.Client, error) {
	return google.DefaultClient(ctx, iam.CloudPlatformScope)
}
