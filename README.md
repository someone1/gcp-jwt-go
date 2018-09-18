# gcp-jwt-go (v2) [![GoDoc](https://godoc.org/gopkg.in/someone1/gcp-jwt-go.v2?status.svg)](https://godoc.org/gopkg.in/someone1/gcp-jwt-go.v2) [![Go Report Card](https://goreportcard.com/badge/gopkg.in/someone1/gcp-jwt-go.v2)](https://goreportcard.com/report/gopkg.in/someone1/gcp-jwt-go.v2) [![Build Status](https://travis-ci.org/someone1/gcp-jwt-go.svg?branch=v2)](https://travis-ci.org/someone1/gcp-jwt-go) [![Coverage Status](https://coveralls.io/repos/github/someone1/gcp-jwt-go/badge.svg?branch=v2)](https://coveralls.io/github/someone1/gcp-jwt-go?branch=v2)

Google Cloud Platform (KMS, IAM & AppEngine) jwt-go implementations

## New with V2:

Google Cloud KMS [now supports signatures](https://cloud.google.com/kms/docs/create-validate-signatures) and support has been added to gcp-jwt-go!

## Breaking Changes with V2

- Package name changed from gcp_jwt to gcpjwt
- Refactoring of code (including exported functions/structs)
- Certificate caching is now opt-in vs opt-out

To continue using the older version, please import as follows: `import "gopkg.in/someone1/gcp-jwt-go.v1"`

### Other Features

gcp-jwt-go has a basic implementation of using the [IAM SignJwt API](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signJwt) on Google Cloud Platform to sign JWT tokens using the dgrijalva/jwt-go package. Should work across most environments (including AppEngine)!

The old method of using the [IAM SignBlob API](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signBlob) is still supported.

## AppEngine Only (legacy)

Basic implementation of using the built-in [App Identity API](https://cloud.google.com/appengine/docs/go/appidentity/) of AppEngine to sign JWT tokens using the dgrijalva/jwt-go package.

## Basic usage (using the IAM API):

### Setup

```go
import (
    "github.com/someone1/gcp-jwt-go"
)

func init() {
    // Unless we want to keep the original RS256 implementation alive, override it (recommended)
    gcpjwt.SigningMethodIAMJWT.Override() // For signJwt
    // OR
    gcpjwt.SigningMethodIAMBlob.Override() // For signBlob
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
    token := jwt.New(gcpjwt.SigningMethodGCPJWT)
    config := &gcpjwt.IAMConfig{
        ServiceAccount: "app-id@appspot.gserviceaccount.com",
        IAMType:        gcpjwt.IAMJwtType, // or gcpjwt.IAMBlobType
    }
    ctx := gcpjwt.NewIAMContext(context.Background(), config)
    token.Method = gcpjwt.SigningMethodIAMJWT // or gcpjwt.SigningMethodIAMBlob

    // Fill in Token claims

    // For signBlob
    tokenString, err := token.SignedString(ctx)

    // For signJwt
    // !!IMPORTANT!! Due to the way the signJwt API returns tokens, we can't use the standard signing process
    // to sign
    signingString, err := token.SigningString()
    // handle err
    tokenString, terr := token.Method.Sign(signingString, ctx)
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
    config := &gcpjwt.IAMConfig{
        ServiceAccount: "app-id@appspot.gserviceaccount.com",
        IAMType:        gcpjwt.IAMJwtType, // or gcpjwt.IAMBlobType
    }
    config.EnableCache = true // Enable certificates cache

    // To Verify (if we called Override() for our method type prior)
    token, err := jwt.Parse(tokenString, gcpjwt.VerfiyKeyfunc(context.Background(), config))

    // If we DID NOT call the Override() function
    // This is basically copying the https://github.com/dgrijalva/jwt-go/blob/master/parser.go#L23 ParseWithClaims function here but forcing our own method vs getting one based on the Alg field
    // Or Try and parse, Ignore the result and try with the proper method:
    token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return nil, nil
    })
    parts := strings.Split(token.Raw, ".")
    token.Method = gcpjwt.SigningMethodIAMJWT // or gcpjwt.SigningMethodIAMBlob
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
token := jwt.New(gcpjwt.SigningMethodAppEngine)

// OR

token := jwt.New(gcpjwt.SigningMethodGCP)
config := &gcpjwt.IAMSignBlobConfig{
    ServiceAccount: "app-id@appspot.gserviceaccount.com",
}
ctx := gcpjwt.NewContext(ctx, config)

// Pass in a context.Context as the key for Sign/Verify
// Same process as any other signing method in the jwt-go package
```

## Tips

- Create a separate service account to sign on behalf of for your projects unless you NEED to use your default service account (e.g. the AppEngine service account). This way you can limit the scope of access for any leaked credentials. You'll have to grant the `roles/iam.serviceAccountTokenCreator` role to any user/group/serviceaccount you want to be able to sign on behalf of the new service account (resource: `projects/-/serviceAccounts/<serviceaccount>`).
- If using outside of GCP, be sure to put credentials for an account that can access the service account for signing tokens in a well known location:
  1. A JSON file whose path is specified by the GOOGLE_APPLICATION_CREDENTIALS environment variable.
  2. A JSON file in a location known to the gcloud command-line tool. On Windows, this is %APPDATA%/gcloud/application_default_credentials.json. On other systems, $HOME/.config/gcloud/application_default_credentials.json.
