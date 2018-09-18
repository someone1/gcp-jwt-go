package gcpjwt

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/api/iam/v1"
)

var (
	// SigningMethodIAMBlob implements signing JWTs with the IAM signBlob API.
	// https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signBlob
	SigningMethodIAMBlob *SigningMethodIAM
)

func init() {
	SigningMethodIAMBlob = &SigningMethodIAM{
		alg:      "IAMBlob",
		sign:     signBlob,
		override: jwt.SigningMethodRS256.Alg(),
	}
	jwt.RegisterSigningMethod(SigningMethodIAMBlob.Alg(), func() jwt.SigningMethod {
		return SigningMethodIAMBlob
	})
}

func signBlob(ctx context.Context, iamService *iam.Service, config *IAMConfig, signingString string) (string, error) {
	// Prepare the call
	signReq := &iam.SignBlobRequest{
		BytesToSign: base64.StdEncoding.EncodeToString([]byte(signingString)),
	}
	name := fmt.Sprintf("projects/%s/serviceAccounts/%s", config.ProjectID, config.ServiceAccount)

	// Do the call
	signResp, err := iamService.Projects.ServiceAccounts.SignBlob(name, signReq).Context(ctx).Do()
	if err != nil {
		return "", err
	}

	// Check the response
	if signResp.HTTPStatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected response code from signing request, expected %d but got %d instead", http.StatusOK, signResp.HTTPStatusCode)
	}

	config.lastKeyID = signResp.KeyId

	signature, err := base64.StdEncoding.DecodeString(signResp.Signature)
	if err != nil {
		return "", err
	}

	return jwt.EncodeSegment(signature), nil
}
