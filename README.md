# gcp-jwt-go
Google Cloud Platform (IAM & AppEngine) jwt-go implementations

Basic implementation of using the [IAM SignBlob API](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signBlob) on Google Cloud Platform to sign JWT tokens using the dgrijalva/jwt-go package. Should work across most environments (including AppEngine)!

## AppEngine Only
Basic implementation of using the built-in [App Identity API](https://cloud.google.com/appengine/docs/go/appidentity/) of AppEngine to sign JWT tokens using the dgrijalva/jwt-go package.

## Basic usage:

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
