package gcpjwt

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Public/Private key is hardcoded in dev server and found in
// google.appengine.api.app_identity.app_identity_stub

// Private Key:
// -----BEGIN RSA PRIVATE KEY-----
// MIICIQIBAAKCAQEAl3RgkJBa9Axr7sv+isK3cPSFW2R0CR4ZKKS5PhTuY2vEG45o
// BvEIgaFFtR7an669EXoxm0u+hTWH2oQWj/ABUM4c3hYeHDdUuX85W6t51F97xsFO
// LQqp2BQGsqvxXrWfbo3cHgxr12RMxtw4ML9cJ88hEmdMh/hnW+egR9ZAQkN9b1As
// kXIkXXuGmn2XlLW64wkHGNgyxncTEupIWEzshs3U8MEBvrMa0jtv0BU/6DFLWGNe
// ImhkDfYhYg0BmI9X7ST3bl5yxXQGQjTNXhNrToUl7E3HTjTLmK+vgLbXgZFQzdQq
// KGKtNwQ4FLVrtJGLnAI+H/BPQDyA3o01tM2NzQIDAQABAoIBAQCGjxzkE3zbatXR
// +WeS/OBh+L0qr5rwJs+Pbpot8AbEShCXsvP1htxZ32DBREJUsLjF+FxubuM8Eo06
// tTQeecuRcS3wmpHx267oh4H8UeMRriuYMFI2bkzr7w7sWxs9W/vkCyFPiRWe7jvQ
// SgOaO8myjLIDWceC3k1mN+oNKOs6cr+rdMDX+dZNrMglvD8nStt40MF1EuQZdgpr
// R7ozsAH2NM49JFhjXz4wQGoETIFYBNU3QlVRY0WaHV+1vlDo+Ly3YJ1S+2pgfgAa
// qX47X+W8+Rp6qU+RB7Zx1O1RENI3k2BfW9P8lQz1JfHdffPMRZwQOgjl5CbhOu5U
// qoE/YF+5AgEDAgEFAgEBAgEBAgEC
// -----END RSA PRIVATE KEY-----

// Public Key:
// -----BEGIN CERTIFICATE-----
// MIIC/jCCAeagAwIBAgIIQTBFcRw3moMwDQYJKoZIhvcNAQEFBQAwIjEgMB4GA1UE
// AxMXcm9ib3RqYXZhLmEuYXBwc3BvdC5jb20wHhcNMTEwMjIzMTUwNzQ5WhcNMTEw
// MjI0MTYwNzQ5WjAiMSAwHgYDVQQDExdyb2JvdGphdmEuYS5hcHBzcG90LmNvbTCC
// ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJd0YJCQWvQMa+7L/orCt3D0
// hVtkdAkeGSikuT4U7mNrxBuOaAbxCIGhRbUe2p+uvRF6MZtLvoU1h9qEFo/wAVDO
// HN4WHhw3VLl/OVuredRfe8bBTi0KqdgUBrKr8V61n26N3B4Ma9dkTMbcODC/XCfP
// IRJnTIf4Z1vnoEfWQEJDfW9QLJFyJF17hpp9l5S1uuMJBxjYMsZ3ExLqSFhM7IbN
// 1PDBAb6zGtI7b9AVP+gxS1hjXiJoZA32IWINAZiPV+0k925ecsV0BkI0zV4Ta06F
// JexNx040y5ivr4C214GRUM3UKihirTcEOBS1a7SRi5wCPh/wT0A8gN6NNbTNjc0C
// AwEAAaM4MDYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/
// BAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQEFBQADggEBAD+h2D+XGIHWMwPCA2DN
// JgMhN1yTTJ8dtwbiQIhfy8xjOJbrzZaSEX8g2gDm50qaEl5TYHHr2zvAI1UMWdR4
// nx9TN7I9u3GoOcQsmn9TaOKkBDpMv8sPtFBal3AR5PwR5Sq8/4L/M22LX/TN0eIF
// Y4LnkW+X/h442N8a1oXn05UYtFo+p/6emZb1S84WZAnONGtF5D1Z6HuX4ikDI5m+
// iZbwm47mLkV8yuTZGKI1gJsWmAsElPkoWVy2X0t69ecBOYyn3wMmQhkLk2+7lLlD
// /c4kygP/941fe1Wb/T9yGeBXFwEvJ4jWbX93Q4Xhk9UgHlso9xkCu9QeWFvJqufR
// 5Cc=
// -----END CERTIFICATE-----

// TODO: Figure out why AppEngine has hardcoded certs but isn't returning values for them!

var appEngineTestData = []struct {
	name        string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"AppEngine",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.YgMNm6dQvP0H5ZQC6xheyzCJ7tuz3BYh6YMNVCDNHX58zgbodNVRMgR26hpCtxvnXkz-98Qd_lHcbCeIr8dWLNmt_EOLYXgTTnYoy8qCwnOFj62wnIBamxo684HIDbkoGk3rblbu8LIVA4cPm0_dFnyCcHM1hMao_HhaAb9rxVYA923q2Oi1-MhoVRbpTnru2GNvp8SzWR1KSPFedtxnr9K4iEv8jnuMHIgtvY1FVOxRCTHF6Whqq-YrD0ruqwpEYhMzPPTkqN5KB7EOjg-Am72DPH-eH8aQ40yju-Jb8knVj0IFfbrZl7UhPJ2Gz2WGkAi7aeeUnNIPdUkuS3gd5w",
		"AppEngine",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"basic invalid: foo => bar",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		"AppEngine",
		map[string]interface{}{"foo": "bar"},
		false,
	},
}

// func TestAppEngineVerify(t *testing.T) {
// 	c, err := newContextFunc()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	verifyFunc := AppEngineVerfiyKeyfunc(c, true, time.Hour)

// 	aeCerts, err := appengine.PublicCertificates(c)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	for _, cert := range aeCerts {
// 		t.Logf("%s:\n%s", cert.KeyName, string(cert.Data))
// 	}

// 	for _, data := range appEngineTestData {
// 		t.Run(data.name, func(t *testing.T) {
// 			parts := strings.Split(data.tokenString, ".")
// 			token := new(jwt.Token)
// 			token, parts, err = new(jwt.Parser).ParseUnverified(data.tokenString, &jwt.MapClaims{})
// 			if err != nil {
// 				t.Errorf("Error while parsing token: %v", err)
// 				return
// 			}
// 			method := jwt.GetSigningMethod(data.alg)
// 			token.Method = method
// 			key, err := verifyFunc(token)
// 			if err != nil {
// 				t.Errorf("Error while getting key: %v", err)
// 				return
// 			}

// 			err = method.Verify(strings.Join(parts[0:2], "."), parts[2], key)
// 			if data.valid && err != nil {
// 				t.Errorf("Error while verifying key: %v", err)
// 			}
// 			if !data.valid && err == nil {
// 				t.Errorf("Invalid key passed validation")
// 			}
// 		})
// 	}
// }
//
// func TestAppEngineSign(t *testing.T) {
// 	c, close, err := aetest.NewContext()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer close()
// 	for _, data := range appEngineTestData {
// 		t.Run(data.name, func(t *testing.T) {
// 			if data.valid {
// 				parts := strings.Split(data.tokenString, ".")
// 				method := jwt.GetSigningMethod(data.alg)
// 				if _, ok := method.(*SigningMethodAppEngineImpl); !ok {
// 					t.Errorf("incorrect method grabbed for alg `%s`", data.alg)
// 					return
// 				}
// 				sig, err := method.Sign(strings.Join(parts[0:2], "."), c)
// 				if err != nil {
// 					t.Errorf("Error signing token: %v", err)
// 					return
// 				}
// 				if sig != parts[2] {
// 					t.Errorf("Incorrect signature.\nwas:\n%v\nexpecting:\n%v", sig, parts[2])
// 					return
// 				}

// 				if SigningMethodAppEngine.KeyID() == "" {
// 					t.Errorf("Expected non-empty key id after signing token, got `%s`", SigningMethodAppEngine.KeyID())
// 				}
// 			}
// 		})
// 	}
// }

func TestAppEngineSignAndVerify(t *testing.T) {
	if !isAppEngine {
		return
	}
	ctx, err := newContextFunc()
	if err != nil {
		t.Errorf("could not get context: %v", err)
		return
	}

	for _, data := range appEngineTestData {
		t.Run(data.name, func(t *testing.T) {
			parts := strings.Split(data.tokenString, ".")
			method := jwt.GetSigningMethod(data.alg)
			sig, err := method.Sign(strings.Join(parts[0:2], "."), ctx)
			if err != nil {
				t.Errorf("Error signing token: %v", err)
				return
			}

			if SigningMethodAppEngine.KeyID() == "" {
				t.Errorf("Expected non-empty key id after calling sign")
				return
			}

			token := new(jwt.Token)
			token.Method = method
			keyFunc := AppEngineVerfiyKeyfunc(ctx, true, time.Hour)
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

func TestSigningMethodAppEngineImpl_Sign(t *testing.T) {
	if !isAppEngine {
		return
	}
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SigningMethodAppEngine.Sign(tt.args.signingString, tt.args.key)
			if err != tt.wantErr {
				t.Errorf("SigningMethodAppEngine.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
