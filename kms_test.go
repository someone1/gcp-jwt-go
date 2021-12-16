package gcpjwt

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

type testKey struct {
	Name    string `json:"name"`
	Alg     string `json:"alg"`
	KeyPath string `json:"key_path"`
	KeyID   string `json:"key_id"`
}

func readKeys() ([]testKey, error) {
	path := os.Getenv("KMS_TEST_KEYS")
	if path == "" {
		return nil, fmt.Errorf("environmental variable KMS_TEST_KEYS missing")
	}

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	testKeys := make([]testKey, 0)
	err = json.Unmarshal(b, &testKeys)
	if err != nil {
		return nil, err
	}

	return testKeys, err
}

func algToMethod(alg string) jwt.SigningMethod {
	switch alg {
	case "RS256":
		return SigningMethodKMSRS256
	case "PS256":
		return SigningMethodKMSPS256
	case "ES256":
		return SigningMethodKMSES256
	case "ES384":
		return SigningMethodKMSES384
	}
	return nil
}

func TestKMSSignAndVerify(t *testing.T) {
	testKeys, err := readKeys()
	if err != nil {
		t.Errorf("could not read keys: %v", err)
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
			method := algToMethod(tt.Alg)
			if method == nil {
				t.Errorf("Uknown alg = %s", tt.Alg)
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

func TestSigningMethodKMS_Hash(t *testing.T) {
	type fields struct {
		alg      string
		override jwt.SigningMethod
		hasher   crypto.Hash
	}
	tests := []struct {
		name   string
		fields fields
		want   crypto.Hash
	}{
		{
			"SimpleTest",
			fields{
				"RS256",
				jwt.SigningMethodRS256,
				jwt.SigningMethodRS256.Hash,
			},
			jwt.SigningMethodRS256.Hash,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SigningMethodKMS{
				alg:      tt.fields.alg,
				override: tt.fields.override,
				hasher:   tt.fields.hasher,
			}
			if got := s.Hash(); got != tt.want {
				t.Errorf("SigningMethodKMS.Hash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKMSVerfiyKeyfunc(t *testing.T) {
	ctx, err := newContextFunc()
	if err != nil {
		t.Errorf("could not get context: %v", err)
		return
	}
	testKeys, err := readKeys()
	if err != nil {
		t.Errorf("could not read keys: %v", err)
		return
	}
	if len(testKeys) < 1 {
		t.Errorf("no keys to test with")
		return
	}
	type args struct {
		ctx    context.Context
		config *KMSConfig
		token  *jwt.Token
	}
	tests := []struct {
		name           string
		args           args
		wantKeyFuncErr bool
		wantErr        bool
	}{
		{
			"WrongMethod",
			args{
				ctx,
				&KMSConfig{
					KeyPath: testKeys[0].KeyPath,
				},
				&jwt.Token{
					Method: jwt.SigningMethodPS256,
					Header: map[string]interface{}{
						"alg": "PS256",
					},
				},
			},
			false,
			true,
		},
		{
			"InvalidKeyPath",
			args{
				ctx,
				&KMSConfig{
					KeyPath: "invalid",
				},
				&jwt.Token{
					Method: SigningMethodKMSES256,
					Header: map[string]interface{}{
						"alg": SigningMethodKMSES256.Alg(),
					},
				},
			},
			true,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if keyFunc, gotErr := KMSVerfiyKeyfunc(tt.args.ctx, tt.args.config); (gotErr != nil) != tt.wantKeyFuncErr {
				t.Errorf("VerifyKeyfunc() error = %v, wantErr %v", gotErr, tt.wantKeyFuncErr)
			} else if gotErr == nil {
				if _, gotErr = keyFunc(tt.args.token); (gotErr != nil) != tt.wantErr {
					t.Errorf("VerifyKeyfunc().Keyfunc() error = %v, wantErr %v", gotErr, tt.wantErr)
				}
			}
		})
	}
}
