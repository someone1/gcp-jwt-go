package gcpjwt

import (
	"context"
	"testing"

	"google.golang.org/api/iamcredentials/v1"
)

func Test_signJwt(t *testing.T) {
	type args struct {
		ctx           context.Context
		iamService    *iamcredentials.Service
		config        *IAMConfig
		signingString string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"OnePartSigningString",
			args{
				context.Background(),
				nil,
				nil,
				"onepart",
			},
			"",
			true,
		},
		{
			"InvalidEncoding",
			args{
				context.Background(),
				nil,
				nil,
				"header.invalidclaims",
			},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := signJwt(tt.args.ctx, tt.args.iamService, tt.args.config, tt.args.signingString)
			if (err != nil) != tt.wantErr {
				t.Errorf("signJwt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("signJwt() = %v, want %v", got, tt.want)
			}
		})
	}
}
