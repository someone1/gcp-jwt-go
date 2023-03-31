package gcpjwt

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/api/iamcredentials/v1"
)

var (
	// SigningMethodIAMJWT implements signing JWTs with the IAM signJwt API.
	// https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt
	SigningMethodIAMJWT *SigningMethodIAM
)

func init() {
	SigningMethodIAMJWT = &SigningMethodIAM{
		alg:      "IAMJWT", // NOT USED
		sign:     signJwt,
		override: jwt.SigningMethodRS256.Alg(),
	}
	jwt.RegisterSigningMethod(SigningMethodIAMJWT.Alg(), func() jwt.SigningMethod {
		return SigningMethodIAMJWT
	})
}

func signJwt(ctx context.Context, iamService *iamcredentials.Service, config *IAMConfig, signingString string) (string, error) {
	// Prepare the call
	// First decode the JSON string and discard the header
	parts := strings.Split(signingString, ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("gcpjwt: expected a 2 part string to sign, got %d parts", len(parts))
	}
	jwtClaimSet, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		return "", err
	}

	signReq := &iamcredentials.SignJwtRequest{Payload: string(jwtClaimSet)}
	name := fmt.Sprintf("projects/-/serviceAccounts/%s", config.ServiceAccount)

	// Do the call
	signResp, err := iamService.Projects.ServiceAccounts.SignJwt(name, signReq).Context(ctx).Do()
	if err != nil {
		return "", err
	}

	config.Lock()
	defer config.Unlock()

	config.lastKeyID = signResp.KeyId

	return signResp.SignedJwt, nil
}
