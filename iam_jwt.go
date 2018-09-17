package gcpjwt

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/api/iam/v1"
)

var (
	// SigningMethodIAMJWT implements signing JWTs with
	// the IAM signJwt API.
	// https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signJwt
	SigningMethodIAMJWT *signingMethodIAM
)

func init() {
	SigningMethodIAMJWT = &signingMethodIAM{
		alg:  "IAMJWT", // NOT USED
		sign: signJwt,
	}
	jwt.RegisterSigningMethod(SigningMethodIAMJWT.Alg(), func() jwt.SigningMethod {
		return SigningMethodIAMJWT
	})
}

// OverrideRS256WithIAMJWT will replace the original RS256 method with the signJwt method
func OverrideRS256WithIAMJWT() {
	SigningMethodIAMJWT.alg = jwt.SigningMethodRS256.Alg()
	jwt.RegisterSigningMethod(jwt.SigningMethodRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodIAMJWT
	})
}

func signJwt(ctx context.Context, iamService *iam.Service, config *IAMConfig, signingString string) (string, error) {
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

	signReq := &iam.SignJwtRequest{Payload: string(jwtClaimSet)}
	name := fmt.Sprintf("projects/%s/serviceAccounts/%s", config.ProjectID, config.ServiceAccount)

	// Do the call
	signResp, err := iamService.Projects.ServiceAccounts.SignJwt(name, signReq).Context(ctx).Do()
	if err != nil {
		return "", err
	}

	// Check the response
	if signResp.HTTPStatusCode != http.StatusOK {
		return "", fmt.Errorf("gcpjwt: expected response code `%d` from signing request, got `%d`", http.StatusOK, signResp.HTTPStatusCode)
	}

	return signResp.SignedJwt, nil
}
