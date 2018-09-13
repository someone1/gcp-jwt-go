package gcpjwt_test

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/someone1/gcp-jwt-go"
	"golang.org/x/net/context"
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
		"GCP",
		map[string]interface{}{"foo": "bar"},
		false,
	},
	{
		"basic jwt invalid: foo => bar",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		"GCPJWT",
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

func TestGCPVerify(t *testing.T) {
	config := &gcpjwt.IAMSignBlobConfig{
		ServiceAccount: jwtConfig.Email,
	}
	configJWT := &gcpjwt.IAMSignJWTConfig{
		ServiceAccount: jwtConfig.Email,
	}
	c := gcpjwt.NewContextJWT(gcpjwt.NewContext(context.Background(), config), configJWT)
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

func TestGCPSign(t *testing.T) {
	config := &gcpjwt.IAMSignBlobConfig{
		ServiceAccount: jwtConfig.Email,
	}
	configJWT := &gcpjwt.IAMSignJWTConfig{
		ServiceAccount: jwtConfig.Email,
	}
	c := gcpjwt.NewContextJWT(gcpjwt.NewContext(context.Background(), config), configJWT)
	for _, data := range gcpTestData {
		parts := strings.Split(data.tokenString, ".")
		method := jwt.GetSigningMethod(data.alg)
		sig, err := method.Sign(strings.Join(parts[0:2], "."), c)
		if err != nil {
			t.Errorf("[%v] Error signing token: %v", data.name, err)
		}

		if data.alg == "GCPJWT" {
			parts = strings.Split(sig, ".")
			sig = parts[2]
		}

		// With Cache
		config.DisableCache = false
		configJWT.DisableCache = false
		err = method.Verify(strings.Join(parts[0:2], "."), sig, c)
		if err != nil {
			t.Errorf("[%v] Error verifying token (with cache): %v", data.name, err)
		}

		// Without Cache
		config.DisableCache = true
		configJWT.DisableCache = true
		err = method.Verify(strings.Join(parts[0:2], "."), sig, c)
		if err != nil {
			t.Errorf("[%v] Error verifying token (without cache): %v", data.name, err)
		}
	}
}

func TestOverrideRS256(t *testing.T) {
	method := jwt.GetSigningMethod("RS256")
	if method.Alg() != "RS256" {
		t.Errorf("Expected Alg() == RS256, got %v instead", method.Alg())
	}

	gcpjwt.OverrideRS256()
	method = jwt.GetSigningMethod("RS256")
	if method.Alg() == "RS256" {
		t.Errorf("Expected Alg() != RS256, got %v instead", method.Alg())
	}
}
