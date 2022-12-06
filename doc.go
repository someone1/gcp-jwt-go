/*
Package gcpjwt has Google Cloud Platform (Cloud KMS, IAM API, & AppEngine App Identity API) jwt-go implementations.
Should work across virtually all environments, on or off of Google's Cloud Platform.

# Getting Started

It is highly recommended that you override the default algorithm implementations that you want to leverage a GCP service
for in dgrijalva/jwt-go. You otherwise will have to manually pick the verification method for your JWTs and they will
place non-standard headers in the rendered JWT (with the exception of signJwt from the IAM API which overwrites the
header with its own).

You should only need to override the algorithm(s) you plan to use. It is also incorrect to override overlapping,
algorithms such as `gcpjwt.SigningMethodKMSRS256.Override()` and `gcpjwt.SigningMethodIAMJWT.Override()`

Example:

	import (
		"github.com/someone1/gcp-jwt-go"
	)

	func init() {
		// Pick one or more of the following to override

		// Cloud KMS
		gcpjwt.SigningMethodKMSRS256.Override() // RS256
		gcpjwt.SigningMethodKMSPS256.Override() // PS256
		gcpjwt.SigningMethodKMSES256.Override() // ES256
		gcpjwt.SigningMethodKMSES384.Override() // ES384

		// IAM API - This implements RS256 exclusively
		gcpjwt.SigningMethodIAMJWT.Override() // For signJwt
		gcpjwt.SigningMethodIAMBlob.Override() // For signBlob

		// AppEngine - Standard runtime only, does not apply to Flexible runtime, implements RS256 exclusively
		// You can also use any of the above methods on AppEngine Standard
		gcpjwt.SigningMethodAppEngine.Override()
	}

As long as a you override a default algorithm implementation as shown above, using the dgrijalva/jwt-go is mostly unchanged.

# Create a Token

Token creation is more/less done the same way as in the dgrijalva/jwt-go package. The key that you need to provide is
always going to be a context.Context, usuaully with a configuration object loaded in:
  - use gcpjwt.IAMConfig for the SigningMethodIAMJWT and SigningMethodIAMBlob signing methods
  - use an appengine.NewContext for the SigningMethodAppEngine signing method
  - use gcpjwt.KMSConfig for any of the KMS signing methods

Example:

	import (
		"context"
		"net/http"

		"github.com/golang-jwt/jwt/v4"
		"github.com/someone1/gcp-jwt-go"
		"google.golang.org/appengine" // only on AppEngine Standard when using the SigningMethodAppEngine signing method
	)

	func makeToken(ctx context.Context) (string, error) string {
		// Important - if on AppEngine standard, even if you aren't using the SigningMethodAppEngine signing method
		// you must pass around the appengine.NewContext context as it is required for the API calls all methods must
		// make.

		var key interface{}
		claims := &jwt.StandardClaims{
			ExpiresAt: 15000,
			Issuer:    "test",
		}
		token := jwt.NewWithClaims(gcpjwt.SigningMethodGCPJWT, claims)

		// Prepare your signing key

		// For SigningMethodIAMJWT or SigningMethodIAMBlob
		config := &gcpjwt.IAMConfig{
			ServiceAccount: "app-id@appspot.gserviceaccount.com",
			IAMType:        gcpjwt.IAMJwtType, // or gcpjwt.IAMBlobType
		}
		key = gcpjwt.NewIAMContext(ctx, config)

		// For any KMS signing method
		config := &gcpjwt.KMSConfig{
			KeyPath: "name=projects/<project-id>/locations/<location>/keyRings/<key-ring-name>/cryptoKeys/<key-name>/cryptoKeyVersions/<key-version>",
		}
		key = gcpjwt.NewKMSContext(ctx, config)

		// For SigningMethodAppEngine
		key = ctx

		// For all signing methods EXCEPT signJWT
		return token.SignedString(key)

		// For signJwt
		// !!IMPORTANT!! Due to the way the signJwt API returns tokens, we can't use the standard signing process
		// to sign
		signingString, err := token.SigningString()
		if err != nil {
			return "", err
		}

		return token.Method.Sign(signingString, key)
	}

# Validate a Token

Finally, the steps to validate a token should be straight forward. This library provides you with helper jwt.Keyfunc
implementations to do the heavy lifting around getting the public certificates for verification:

  - gcpjwt.IAMVerfiyKeyfunc can be used for the IAM API and the AppEngine Standard signing methods
  - gcpjwt.AppEngineVerfiyKeyfunc is only available on AppEngine standard and can only be used on JWT signed from the same default service account as the running application
  - gcp.KMSVerfiyKeyfunc can be used for the Cloud KMS signing methods

Example:

	import (
		"context"
		"time"
		"strings"

		"github.com/golang-jwt/jwt/v4"
		"github.com/someone1/gcp-jwt-go"
	)

	func validateToken(ctx context.Context, tokenString string) (*jwt.Token, error) {
		// Important - if on AppEngine standard, even if you aren't using the SigningMethodAppEngine signing method
		// you must pass around the appengine.NewContext context as it is required for the API calls all methods must
		// make.

		var keyFunc jwt.Keyfunc

		// Prepare your key function

		// For SigningMethodIAMJWT or SigningMethodIAMBlob or SigningMethodAppEngine
		config := &gcpjwt.IAMConfig{
			ServiceAccount: "app-id@appspot.gserviceaccount.com",
			IAMType:        gcpjwt.IAMJwtType, // or gcpjwt.IAMBlobType (use the Blob type if you used the SigningMethodAppEngine before)
			EnableCache:    true, // Enable the certificate cache so we don't fetch it on every verification - RECOMMENDED
		}
		keyFunc = gcpjwt.IAMVerfiyKeyfunc(ctx, config)

		// For any KMS signing method
		config := &gcpjwt.KMSConfig{
			KeyPath: "name=projects/<project-id>/locations/<location>/keyRings/<key-ring-name>/cryptoKeys/<key-name>/cryptoKeyVersions/<key-version>",
		}
		keyFunc = gcpjwt.KMSVerfiyKeyfunc(ctx, config)

		// For SigningMethodAppEngine only on AppEngine Standard
		keyFunc = gcpjwt.AppEngineVerfiyKeyfunc(ctx, true, time.Hour)

		// If you called an Override function as recommended above, for both signing and verifying a token, you can use
		// the regular verification steps - and the same goes if you did NOT call it for both signing and verifying (using non-standard 'alg' headers)
		// EXCEPT for the signJwt IAM API signing method which overwrites the header's alg to RS256
		return jwt.Parse(tokenString, keyFunc)

		// The following is an extreme and advanced use-case - it is NOT recommended but here for those who need it.
		//
		// If we need to manually override the detected jwt.SigningMethod based on the 'alg' header
		// This is basically copying the https://github.com/golang-jwt/jwt/v4/blob/master/parser.go#L23 ParseWithClaims function here but forcing our own method vs getting one based on the Alg field
		// Or Try and parse, Ignore the result and try with the proper method:
		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return nil, nil
		})
		parts := strings.Split(token.Raw, ".")
		token.Method = gcpjwt.SigningMethodIAMJWT // or whichever method you want to force
		if err := token.Method.Verify(strings.Join(parts[0:2], "."), token.Signature, keyFunc); err != nil {
			return nil, err
		} else {
			token.Valid = true
		}
		return token, nil
	}
*/
package gcpjwt
