package gcpjwt

import (
	"context"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2/google"
	gjwt "golang.org/x/oauth2/jwt"
)

var jwtConfig *gjwt.Config

var gcpTestData = []struct {
	name        string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"basic gcp invalid: foo => bar",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		"IAMBlob",
		map[string]interface{}{"foo": "bar"},
		false,
	},
	{
		"basic jwt invalid: foo => bar",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		"IAMJWT",
		map[string]interface{}{"foo": "bar"},
		false,
	},
}

func init() {
	credPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credPath == "" {
		panic("GOOGLE_APPLICATION_CREDENTIALS environmental variable required for this test to run!")
	}

	b, err := ioutil.ReadFile(credPath)
	if err != nil {
		panic(err)
	}

	jwtConfig, err = google.JWTConfigFromJSON(b)
	if err != nil {
		panic(err)
	}
}

func TestIAMInvalidVerify(t *testing.T) {
	config := &IAMConfig{
		ServiceAccount: jwtConfig.Email,
	}

	c := NewIAMContext(context.Background(), config)
	for _, data := range gcpTestData {
		parts := strings.Split(data.tokenString, ".")

		method := jwt.GetSigningMethod(data.alg)
		err := method.Verify(strings.Join(parts[0:2], "."), parts[2], c)
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
	}
}

func TestIAMSignAndVerify(t *testing.T) {
	config := &IAMConfig{
		ServiceAccount: jwtConfig.Email,
	}

	c := NewIAMContext(context.Background(), config)
	for _, data := range gcpTestData {
		t.Run(data.alg, func(t *testing.T) {
			parts := strings.Split(data.tokenString, ".")
			method := jwt.GetSigningMethod(data.alg)
			sig, err := method.Sign(strings.Join(parts[0:2], "."), c)
			if err != nil {
				t.Fatalf("[%v] Error signing token: %v", data.name, err)
			}

			token := new(jwt.Token)
			if data.alg == "IAMJWT" {
				// This returns the entire JWT, not just the signature!
				token, parts, err = new(jwt.Parser).ParseUnverified(sig, &jwt.MapClaims{})
				if err != nil {
					t.Fatalf("[%v] Error parsing token: %v", data.name, token)
				}
				sig = parts[2]
			}

			token.Method = method
			keyFunc := VerfiyKeyfunc(c, config)
			key, err := keyFunc(token)
			if err != nil {
				t.Fatalf("[%v] Error getting key: %v", data.name, err)
			}

			err = method.Verify(strings.Join(parts[0:2], "."), sig, key)
			if err != nil {
				t.Errorf("[%v] Error verifying token (with cache): %v", data.name, err)
			}
		})
	}
}

func TestOverrideRS256(t *testing.T) {
	method := jwt.GetSigningMethod("RS256")
	if method.Alg() != "RS256" {
		t.Errorf("Expected Alg() == RS256, got %v instead", method.Alg())
	}

	OverrideRS256WithIAMJWT()
	method = jwt.GetSigningMethod("RS256")
	if method.Alg() != SigningMethodIAMJWT.Alg() {
		t.Errorf("Expected Alg() == `%s`, got `%s` instead", SigningMethodIAMJWT.Alg(), method.Alg())
	}

	OverrideRS256WithIAMBlob()
	method = jwt.GetSigningMethod("RS256")
	if method.Alg() != SigningMethodIAMBlob.Alg() {
		t.Errorf("Expected Alg() == `%s`, got `%s` instead", SigningMethodIAMBlob.Alg(), method.Alg())
	}
}
