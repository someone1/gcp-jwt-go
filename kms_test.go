package gcpjwt

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

type testKey struct {
	Name    string `json:"name"`
	Alg     string `json:"alg"`
	KeyPath string `json:"key_path"`
	KeyID   string `json:"key_id"`
}

func TestKMSSignAndVerify(t *testing.T) {
	testKeysPath := os.Getenv("KMS_TEST_KEYS")
	if testKeysPath == "" {
		t.Skip("KMS_TEST_KEYS environmental variable required for this test to run!")
		return
	}

	b, err := ioutil.ReadFile(testKeysPath)
	if err != nil {
		panic(err)
	}

	testKeys := make([]testKey, 0)
	err = json.Unmarshal(b, &testKeys)
	if err != nil {
		t.Errorf("Could not unmarshal test keys: %v", err)
		return
	}

	testClaims := jwt.MapClaims{
		"foo": "bar",
	}

	ctx, err := newContextFunc()
	if err != nil {
		t.Errorf("could not get new context: %v", err)
		return
	}

	for _, tt := range testKeys {
		t.Run(tt.Name, func(t *testing.T) {
			config := &KMSConfig{
				KeyPath: tt.KeyPath,
			}
			keyFunc, err := KMSVerfiyKeyfunc(ctx, config)
			if err != nil {
				t.Errorf("could not get keyFunc: %v", err)
				return
			}
			newCtx := NewKMSContext(ctx, config)
			var method jwt.SigningMethod
			switch tt.Alg {
			case "RS256":
				method = SigningMethodKMSRS256
			case "PS256":
				method = SigningMethodKMSPS256
			case "ES256":
				method = SigningMethodKMSES256
			case "ES384":
				method = SigningMethodKMSES384
			default:
				t.Errorf("Uknown alg = %s", tt.Alg)
				return
			}

			testTokens := []struct {
				name   string
				token  *jwt.Token
				keyErr bool
			}{
				{
					"NoKID",
					&jwt.Token{
						Header: map[string]interface{}{
							"alg": tt.Alg,
							"typ": "JWT",
						},
						Claims: testClaims,
						Method: method,
					},
					false,
				},
				{
					"ValidKID",
					&jwt.Token{
						Header: map[string]interface{}{
							"alg": tt.Alg,
							"typ": "JWT",
							"kid": tt.KeyID,
						},
						Claims: testClaims,
						Method: method,
					},
					false,
				},
				{
					"WrongKID",
					&jwt.Token{
						Header: map[string]interface{}{
							"alg": tt.Alg,
							"typ": "JWT",
							"kid": "invalid",
						},
						Claims: testClaims,
						Method: method,
					},
					true,
				},
			}
			for _, testToken := range testTokens {
				t.Run(testToken.name, func(t *testing.T) {
					// Sign token
					tokenStr, err := testToken.token.SignedString(newCtx)
					if err != nil {
						t.Errorf("could not sign token: %v", err)
						return
					}

					// Parse token
					token, parts, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
					if err != nil {
						t.Errorf("could not parse token: %v", err)
						return
					}
					token.Method = method

					// Get key
					var key interface{}
					if key, err = keyFunc(token); err != nil {
						if testToken.keyErr {
							return
						}
						t.Errorf("could not get key: %v", err)
						return
					}

					// Verify token
					if err = method.Verify(strings.Join(parts[0:2], "."), parts[2], key); err != nil {
						t.Errorf("could not verify token: %v", err)
						t.Error(tokenStr)
						return
					}
				})
			}
		})
	}
}

func TestSigningMethodKMS_Override(t *testing.T) {
	tests := []struct {
		name string
		s    *SigningMethodKMS
	}{
		{
			"RS256",
			SigningMethodKMSRS256,
		},
		{
			"PS256",
			SigningMethodKMSPS256,
		},
		{
			"ES256",
			SigningMethodKMSES256,
		},
		{
			"ES384",
			SigningMethodKMSES384,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := jwt.GetSigningMethod(tt.s.Alg())
			if method != tt.s {
				t.Errorf("method = `%v`, expected `%v'", method, tt.s)
			}
			tt.s.Override()
			method = jwt.GetSigningMethod(tt.s.override.Alg())
			if method != tt.s {
				t.Errorf("method = `%v`, expected `%v'", method, tt.s)
			}
		})
	}
}

func TestSigningMethodKMS_Sign(t *testing.T) {
	type args struct {
		signingString string
		key           interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			"InvalidKey",
			args{
				"",
				"",
			},
			jwt.ErrInvalidKey,
		},
		{
			"MissingConfig",
			args{
				"",
				context.Background(),
			},
			ErrMissingConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SigningMethodKMSRS256.Sign(tt.args.signingString, tt.args.key)
			if err != tt.wantErr {
				t.Errorf("SigningMethodKMS.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
