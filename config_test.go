package gcpjwt

import (
	"testing"
)

func TestKMSConfig_KeyID(t *testing.T) {
	type fields struct {
		KeyPath string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			"simple",
			fields{
				"simple-key-path",
			},
			"5b20b5c23a39be7870fd1b949032020a51d3eb62",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KMSConfig{
				KeyPath: tt.fields.KeyPath,
			}
			if got := k.KeyID(); got != tt.want {
				t.Errorf("KMSConfig.KeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}
