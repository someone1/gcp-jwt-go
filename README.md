# gcp-jwt-go

Google Cloud Platform (IAM & AppEngine) jwt-go implementations

Basic implementation of using the [IAM SignJwt API](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signJwt) on Google Cloud Platform to sign JWT tokens using the dgrijalva/jwt-go package. Should work across most environments (including AppEngine)!

The old method of using the [IAM SignBlob API](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signBlob) is still supported.

## AppEngine Only (legacy)

Basic implementation of using the built-in [App Identity API](https://cloud.google.com/appengine/docs/go/appidentity/) of AppEngine to sign JWT tokens using the dgrijalva/jwt-go package.

## Basic usage (new - Recommended across all platforms):

### Setup

```go
import (
	"github.com/someone1/gcp-jwt-go"
)

func init() {
	// Unless we want to keep the original RS256 implementation alive, override it (recommended)
    gcp_jwt.OverrideRS256()
}
```

### Create a Token

```go
import (
    "context"

	"github.com/dgrijalva/jwt-go"
	"github.com/someone1/gcp-jwt-go"
)

func makeToken() string {
    method := gcp_jwt.SigningMethodGCPJWT
	token := jwt.New(method)
	config := &gcp_jwt.IAMSignJWTConfig{
		ServiceAccount: "app-id@appspot.gserviceaccount.com",
	}
    ctx := gcp_jwt.NewContextJWT(context.Background(), config)

    // Fill in Token claims

	// !!IMPORTANT!! Due to the way the signJwt API returns tokens, we can't use the standard signing process

	// To Sign
	signingString, err := token.SigningString()
	// handle err
    tokenString, terr := method.Sign(signingString, ctx)
    // handle terr

    return tokenString
}
```

### Validate a Token

```go
import (
    "context"
    "strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/someone1/gcp-jwt-go"
)

func validateToken(tokenString string) {
	config := &gcp_jwt.IAMSignJWTConfig{
		ServiceAccount: "app-id@appspot.gserviceaccount.com",
	}
	ctx := gcp_jwt.NewContextJWT(context.Background(), config)

	// To Verify (if we called OverrideRS256)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// We do NOT have to check the Alg() here as that's done for us in the verification call, only RS256 is used
		return ctx, nil
	})

	// If we DID NOT call OverrideRS256
	// This is basically copying the https://github.com/dgrijalva/jwt-go/blob/master/parser.go#L23 ParseWithClaims function here but forcing our own method vs getting one based on the Alg field
	// Or Try and parse, Ignore the result and try with the proper method:
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})
	parts := strings.Split(token.Raw, ".")
	token.Method = gcp_jwt.SigningMethodGCPJWT
	if err := token.Method.Verify(strings.Join(parts[0:2], "."), token.Signature, ctx); err != nil {
		// handle error
	} else {
        token.Valid = true
    }
}
```

## Basic usage (old - use with AppEngine Standard):

```go
import (
    "github.com/dgrijalva/jwt-go"
    "github.com/someone1/gcp-jwt-go"
)

// AppEngine Only Method
token := jwt.New(gcp_jwt.SigningMethodAppEngine)

// OR

token := jwt.New(gcp_jwt.SigningMethodGCP)
config := &gcp_jwt.IAMSignBlobConfig{
    ServiceAccount: "app-id@appspot.gserviceaccount.com",
}
ctx := gcp_jwt.NewContext(ctx, config)

// Pass in a context.Context as the key for Sign/Verify
// Same process as any other signing method in the jwt-go package
```

## Tips

* Create a separate service account to sign on behalf of for your projects unless you NEED to use your default service account (e.g. the AppEngine service account). This way you can limit the scope of access for any leaked credentials. You'll have to grant the `roles/iam.serviceAccountTokenCreator` role to any user/group/serviceaccount you want to be able to sign on behalf of the new service account (resource: `projects/-/serviceAccounts/<serviceaccount>`).
* If using outside of GCP, be sure to put credentials for an account that can access the service account for signing tokens in a well known location:
  1. A JSON file whose path is specified by the GOOGLE_APPLICATION_CREDENTIALS environment variable.
  2. A JSON file in a location known to the gcloud command-line tool. On Windows, this is %APPDATA%/gcloud/application_default_credentials.json. On other systems, $HOME/.config/gcloud/application_default_credentials.json.
