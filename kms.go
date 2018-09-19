package gcpjwt

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/api/cloudkms/v1"
)

// SigningMethodKMS implements the jwt.SiginingMethod interface for Google's Cloud KMS service
type SigningMethodKMS struct {
	alg      string
	override jwt.SigningMethod
	hasher   crypto.Hash
}

// Support for the Google Cloud KMS Asymmetric Signing Algorithms: https://cloud.google.com/kms/docs/algorithms
var (
	// SigningMethodKMSRS256 leverages Cloud KMS for RS256 algorithms, use with:
	// RSA_SIGN_PKCS1_2048_SHA256
	// RSA_SIGN_PKCS1_3072_SHA256
	// RSA_SIGN_PKCS1_4096_SHA256
	SigningMethodKMSRS256 *SigningMethodKMS
	// SigningMethodKMSPS256 leverages Cloud KMS for PS256 algorithms, use with:
	// RSA_SIGN_PSS_2048_SHA256
	// RSA_SIGN_PSS_3072_SHA256
	// RSA_SIGN_PSS_4096_SHA256
	SigningMethodKMSPS256 *SigningMethodKMS
	// SigningMethodKMSES256 leverages Cloud KMS for the ES256 algorithm, use with:
	// EC_SIGN_P256_SHA256
	SigningMethodKMSES256 *SigningMethodKMS
	// SigningMethodKMSES384 leverages Cloud KMS for the ES256 algorithm, use with:
	// EC_SIGN_P384_SHA384
	SigningMethodKMSES384 *SigningMethodKMS
)

func init() {
	// RS256
	SigningMethodKMSRS256 = &SigningMethodKMS{
		"KMSRS256",
		jwt.SigningMethodRS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodKMSRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodKMSRS256
	})

	// PS256
	SigningMethodKMSPS256 = &SigningMethodKMS{
		"KMSPS256",
		jwt.SigningMethodPS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodKMSPS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodKMSPS256
	})

	// ES256
	SigningMethodKMSES256 = &SigningMethodKMS{
		"KMSES256",
		jwt.SigningMethodES256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodKMSES256.Alg(), func() jwt.SigningMethod {
		return SigningMethodKMSES256
	})

	// ES384
	SigningMethodKMSES384 = &SigningMethodKMS{
		"KMSES384",
		jwt.SigningMethodES384,
		crypto.SHA384,
	}
	jwt.RegisterSigningMethod(SigningMethodKMSES384.Alg(), func() jwt.SigningMethod {
		return SigningMethodKMSES384
	})
}

// Alg will return the JWT header algorithm identifier this method is configured for.
func (s *SigningMethodKMS) Alg() string {
	return s.alg
}

// Override will override the default JWT implementation of the signing function this Cloud KMS type implements.
func (s *SigningMethodKMS) Override() {
	s.alg = s.override.Alg()
	jwt.RegisterSigningMethod(s.alg, func() jwt.SigningMethod {
		return s
	})
}

// Sign implements the Sign method from jwt.SigningMethod. For this signing method, a valid context.Context must be
// passed as the key containing a KMSConfig value.
// https://cloud.google.com/kms/docs/create-validate-signatures#kms-howto-sign-go
func (s *SigningMethodKMS) Sign(signingString string, key interface{}) (string, error) {
	var ctx context.Context

	// check to make sure the key is a context.Context
	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return "", jwt.ErrInvalidKey
	}

	// Get the KMSConfig from the context
	config, ok := KMSFromContext(ctx)
	if !ok {
		return "", ErrMissingConfig
	}

	if !s.hasher.Available() {
		return "", jwt.ErrHashUnavailable
	}

	digest := s.hasher.New()
	digest.Write([]byte(signingString))
	digestStr := base64.StdEncoding.EncodeToString(digest.Sum(nil))

	asymmetricSignRequest := &cloudkms.AsymmetricSignRequest{}
	switch s.hasher {
	case crypto.SHA256:
		asymmetricSignRequest.Digest = &cloudkms.Digest{
			Sha256: digestStr,
		}

	case crypto.SHA384:
		asymmetricSignRequest.Digest = &cloudkms.Digest{
			Sha384: digestStr,
		}
	}

	// ECDSA Signatures from Cloud KMS come ASN1 encoded, which isn't to spec
	// https://tools.ietf.org/html/rfc7518#section-3.4
	var ecdsaMethod *jwt.SigningMethodECDSA
	if method, ok := s.override.(*jwt.SigningMethodECDSA); ok {
		ecdsaMethod = method
	}

	// Do the call
	return signKMS(ctx, config, asymmetricSignRequest, ecdsaMethod)
}

// KMSVerfiyKeyfunc is a helper meant that returns a jwt.Keyfunc. It will handle pulling and selecting the certificates
// to verify signatures with, caching the public key in memory. It is not valid to modify the KMSConfig provided after
// calling this function, you must call this again if changes to the config's KeyPath are made. Note that the public key
// is retrieved when creating the key func and returned for each call to the returned jwt.Keyfunc.
// https://cloud.google.com/kms/docs/retrieve-public-key#kms-howto-retrieve-public-key-go
func KMSVerfiyKeyfunc(ctx context.Context, config *KMSConfig) (jwt.Keyfunc, error) {
	// The Public Key is static for the key version, so grab it now and re-use it as needed
	var publicKey interface{}
	keyVersion := config.KeyID()
	client := config.OAuth2HTTPClient
	if client == nil {
		c, err := getDefaultOauthClient(ctx)
		if err != nil {
			return nil, err
		}
		client = c
	}

	kmsService, err := cloudkms.New(client)
	if err != nil {
		return nil, err
	}
	response, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.GetPublicKey(config.KeyPath).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	if response.HTTPStatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcpjwt: expected response code `%d` from signing request, got `%d`", http.StatusOK, response.HTTPStatusCode)
	}

	keyBytes := []byte(response.Pem)
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("gcpjwt: could not parse certificate from response")
	}
	publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %+v", err)
	}

	return func(token *jwt.Token) (interface{}, error) {
		// Make sure we have the proper header alg
		if _, ok := token.Method.(*SigningMethodKMS); !ok {
			return nil, fmt.Errorf("gcpjwt: unexpected signing method: %v", token.Header["alg"])
		}

		if kid, ok := token.Header["kid"].(string); ok {
			if kid != keyVersion {
				return nil, fmt.Errorf("gcpjwt: unknown kid `%s` found in header", kid)
			}
		}

		return publicKey, nil
	}, nil
}

// Verify does a pass-thru to the appropriate jwt.SigningMethod for this signing algorithm and expects the same key
// https://cloud.google.com/kms/docs/create-validate-signatures#validate_ec_signature
// https://cloud.google.com/kms/docs/create-validate-signatures#validate_rsa_signature
func (s *SigningMethodKMS) Verify(signingString, signature string, key interface{}) error {
	return s.override.Verify(signingString, signature, key)
}

func signKMS(ctx context.Context, config *KMSConfig, request *cloudkms.AsymmetricSignRequest, ecdsaMethod *jwt.SigningMethodECDSA) (string, error) {
	// Default config.OAuth2HTTPClient is a google.DefaultClient
	client := config.OAuth2HTTPClient
	if client == nil {
		c, err := getDefaultOauthClient(ctx)
		if err != nil {
			return "", err
		}
		client = c
	}

	// Prep the service
	kmsService, err := cloudkms.New(client)
	if err != nil {
		return "", err
	}

	// Do the call
	signResp, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.AsymmetricSign(config.KeyPath, request).Context(ctx).Do()
	if err != nil {
		return "", err
	}

	// Check the response
	if signResp.HTTPStatusCode != http.StatusOK {
		return "", fmt.Errorf("gcpjwt: expected response code `%d` from signing request, got `%d`", http.StatusOK, signResp.HTTPStatusCode)
	}

	// Decode the response
	decodedSignature, err := base64.StdEncoding.DecodeString(signResp.Signature)
	if err != nil {
		return "", err
	}

	// If this was signed with the ECDSA algorithm, update the signature to keep it in spec
	if ecdsaMethod != nil {
		var parsedSig struct{ R, S *big.Int }
		_, err = asn1.Unmarshal(decodedSignature, &parsedSig)
		if err != nil {
			return "", fmt.Errorf("gcpjwt: failed to parse ecdsa signature bytes: %+v", err)
		}

		keyBytes := ecdsaMethod.CurveBits / 8
		if ecdsaMethod.CurveBits%8 > 0 {
			keyBytes++
		}

		rBytes := parsedSig.R.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

		sBytes := parsedSig.S.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

		decodedSignature = append(rBytesPadded, sBytesPadded...)
	}

	return jwt.EncodeSegment(decodedSignature), nil
}
