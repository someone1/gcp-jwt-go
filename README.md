# gcp-jwt-go
Google Cloud Platform (AppEngine/Managed VM) jwt-go implementations

Basic implementation of using the built-in [App Identity API](https://cloud.google.com/appengine/docs/go/appidentity/) of AppEngine to sign JWT tokens using the dgrijalva/jwt-go package.

## Basic usage:

```go
import (
    "github.com/dgrijalva/jwt-go"
    _ "github.com/someone1/gcp-jwt-go"
)

token := jwt.New(jwt.GetSigningMethod("AppEngine"))

// Same process as any other signing method in the jwt-go package

```
