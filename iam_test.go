package gcpjwt

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2/google"
	gjwt "golang.org/x/oauth2/jwt"
	"google.golang.org/appengine"
	"google.golang.org/appengine/aetest"
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

var (
	isAppEngine    = os.Getenv("APPENGINE_TEST") == "true"
	newContextFunc = func() (context.Context, error) {
		return context.Background(), nil
	}
)

func TestMain(m *testing.M) {
	close := func() {}
	if isAppEngine {
		inst, err := aetest.NewInstance(nil)
		if err != nil {
			panic(err)
		}
		close = func() {
			inst.Close()
		}
		newContextFunc = func() (context.Context, error) {
			req, err := inst.NewRequest("GET", "/", nil)
			if err != nil {
				return nil, err
			}
			return appengine.NewContext(req), nil
		}
	}
	result := m.Run()
	close()
	os.Exit(result)
}

func TestIAMInvalidVerify(t *testing.T) {
	config := &IAMConfig{
		ServiceAccount: jwtConfig.Email,
	}
	ctx, err := newContextFunc()
	if err != nil {
		t.Errorf("could not get context: %v", err)
		return
	}
	c := NewIAMContext(ctx, config)
	for _, data := range gcpTestData {
		t.Run(data.name, func(t *testing.T) {
			parts := strings.Split(data.tokenString, ".")

			method := jwt.GetSigningMethod(data.alg)
			err := method.Verify(strings.Join(parts[0:2], "."), parts[2], c)
			if data.valid && err != nil {
				t.Errorf("Error while verifying key: %v", err)
			}
			if !data.valid && err == nil {
				t.Errorf("Invalid key passed validation")
			}
		})
	}
}

func TestIAMSignAndVerify(t *testing.T) {
	parts := strings.Split(jwtConfig.Email, "@")
	config := &IAMConfig{
		ServiceAccount: fmt.Sprintf("api-signer@%s", parts[1]),
	}
	ctx, err := newContextFunc()
	if err != nil {
		t.Errorf("could not get context: %v", err)
		return
	}

	c := NewIAMContext(ctx, config)
	for _, data := range gcpTestData {
		t.Run(data.name, func(t *testing.T) {
			parts := strings.Split(data.tokenString, ".")
			method := jwt.GetSigningMethod(data.alg)
			sig, err := method.Sign(strings.Join(parts[0:2], "."), c)
			if err != nil {
				t.Errorf("Error signing token: %v", err)
				return
			}

			if config.KeyID() == "" {
				t.Errorf("Expected non-empty key id after calling sign")
				return
			}

			token := new(jwt.Token)
			if data.alg == "IAMJWT" {
				// This returns the entire JWT, not just the signature!
				token, parts, err = new(jwt.Parser).ParseUnverified(sig, &jwt.MapClaims{})
				if err != nil {
					t.Errorf("Error parsing token: %v", token)
					return
				}
				sig = parts[2]
			}

			token.Method = method
			keyFunc := IAMVerfiyKeyfunc(c, config)
			key, err := keyFunc(token)
			if err != nil {
				t.Errorf("Error getting key: %v", err)
				return
			}

			err = method.Verify(strings.Join(parts[0:2], "."), sig, key)
			if err != nil {
				t.Errorf("Error verifying token (with cache): %v", err)
			}
		})
	}
}

func TestSigningMethodIAM_Override(t *testing.T) {
	method := jwt.GetSigningMethod("RS256")
	if method.Alg() != "RS256" {
		t.Errorf("Expected Alg() == RS256, got %v instead", method.Alg())
	}

	SigningMethodIAMJWT.Override()
	method = jwt.GetSigningMethod("RS256")
	if method != SigningMethodIAMJWT {
		t.Errorf("Expected method == `%T`, got `%T` instead", SigningMethodIAMJWT, method)
	}

	SigningMethodIAMBlob.Override()
	method = jwt.GetSigningMethod("RS256")
	if method != SigningMethodIAMBlob {
		t.Errorf("Expected method == `%T`, got `%T` instead", SigningMethodIAMBlob, method)
	}
}

func TestSigningMethodIAM_Sign(t *testing.T) {
	ctx, err := newContextFunc()
	if err != nil {
		t.Errorf("could not get context: %v", err)
		return
	}
	type args struct {
		signingString string
		key           interface{}
	}
	tests := []struct {
		name       string
		args       args
		method     *SigningMethodIAM
		wantErr    bool
		compareErr error
	}{
		{
			"InvalidKey",
			args{
				"",
				"",
			},
			SigningMethodIAMJWT,
			true,
			jwt.ErrInvalidKey,
		},
		{
			"MissingConfig",
			args{
				"",
				context.Background(),
			},
			SigningMethodIAMJWT,
			true,
			ErrMissingConfig,
		},
		{
			"InvalidServiceAccountJWT",
			args{
				"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ",
				NewIAMContext(ctx, &IAMConfig{ServiceAccount: "invalid"}),
			},
			SigningMethodIAMJWT,
			true,
			nil,
		},
		{
			"InvalidServiceAccountBlob",
			args{
				"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ",
				NewIAMContext(ctx, &IAMConfig{ServiceAccount: "invalid"}),
			},
			SigningMethodIAMBlob,
			true,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, gotErr := tt.method.Sign(tt.args.signingString, tt.args.key); (gotErr != nil) != tt.wantErr || (tt.compareErr != nil && tt.compareErr != gotErr) {
				t.Errorf("%T.Sign() error = %v, wantErr %v, compareErr %v", tt.method, gotErr, tt.wantErr, tt.compareErr)
				return
			}
		})
	}
}

func TestIAMVerfiyKeyfunc(t *testing.T) {
	ctx, err := newContextFunc()
	if err != nil {
		t.Errorf("could not get context: %v", err)
		return
	}
	type args struct {
		ctx    context.Context
		config *IAMConfig
		token  *jwt.Token
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"WrongMethod",
			args{
				ctx,
				&IAMConfig{
					ServiceAccount: jwtConfig.Email,
				},
				&jwt.Token{
					Method: jwt.SigningMethodPS256,
					Header: map[string]interface{}{
						"alg": "PS256",
					},
				},
			},
			true,
		},
		{
			"IncorrectKid",
			args{
				ctx,
				&IAMConfig{
					ServiceAccount: jwtConfig.Email,
				},
				&jwt.Token{
					Method: SigningMethodIAMJWT,
					Header: map[string]interface{}{
						"alg": SigningMethodIAMJWT.Alg(),
						"kid": "invalid",
					},
				},
			},
			true,
		},
		{
			"InvalidServiceAccount",
			args{
				ctx,
				&IAMConfig{
					ServiceAccount: "invalid",
				},
				&jwt.Token{
					Method: SigningMethodIAMJWT,
					Header: map[string]interface{}{
						"alg": SigningMethodIAMJWT.Alg(),
						"kid": "invalid",
					},
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, gotErr := IAMVerfiyKeyfunc(tt.args.ctx, tt.args.config)(tt.args.token); (gotErr != nil) != tt.wantErr {
				t.Errorf("VerifyKeyfunc() error = %v, wantErr %v", gotErr, tt.wantErr)
			}
		})
	}
}
