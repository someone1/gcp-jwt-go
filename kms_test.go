package gcpjwt

import (
	"context"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

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
			method = jwt.GetSigningMethod(tt.s.override)
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
