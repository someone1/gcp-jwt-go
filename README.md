# gcp-jwt-go [![Go Reference](https://pkg.go.dev/badge/github.com/someone1/gcp-jwt-go/v2.svg)](https://pkg.go.dev/github.com/someone1/gcp-jwt-go/v2) [![Go Report Card](https://goreportcard.com/badge/github.com/someone1/gcp-jwt-go)](https://goreportcard.com/report/github.com/someone1/gcp-jwt-go) [![Build Status](https://travis-ci.org/someone1/gcp-jwt-go.svg)](https://travis-ci.org/someone1/gcp-jwt-go) [![Coverage Status](https://coveralls.io/repos/github/someone1/gcp-jwt-go/badge.svg)](https://coveralls.io/github/someone1/gcp-jwt-go)

Google Cloud Platform (Cloud KMS, IAM API, & AppEngine App Identity API) jwt-go implementations

## New with v2:

Google Cloud KMS [now supports signatures](https://cloud.google.com/kms/docs/create-validate-signatures) and support has been added to gcp-jwt-go!

## Breaking Changes with v2.2

- Switched to new iamcredentials API - this no longer allows signBlob to be used on the service account the client is authenticated as.
- `IAMConfig.OAuth2HTTPClient` is deprecrated and unused - Use `IAMConfig.IAMClient` instead.
- `IAMConfig.ProjectID` is deprecrated and unused. The API will infer the project from the service account name.

## Breaking Changes with v2.1

- Dropping support for AppEngine Go 1.9 environment (last version with AppEngine App Identity support will be for Go 1.11)
- KMSConfig no longer takes an optional HTTP Client, but rather the kms gRPC based client
- Middleware will now return a 401 response for unauthenticated requests (previously was returning a 403 response)

## Breaking Changes with v2

- Package name changed from gcp_jwt to gcpjwt
- Refactoring of code (including exported functions/structs)
- Certificate caching is now opt-in vs opt-out
- Helper jwt.Keyfunc implementations introduced
- Expected key for sign/verify changed
- KeyID() helper functions
- Basic oauth2.TokenSource and http middleware sub packages for basic service-to-service authentication (currently only supports IAM Api)

To continue using the older version, please import as follows: `import "gopkg.in/someone1/gcp-jwt-go.v1"`

### Features

gcp-jwt-go has basic implementations of using [Google Cloud KMS](https://cloud.google.com/kms/docs/create-validate-signatures), Google IAM API (both [signJwt](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signJwt) and [signBlob](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signBlob)), and the [App Identity API](https://cloud.google.com/appengine/docs/go/appidentity/) from AppEngine Standard on Google Cloud Platform to sign JWT tokens using the [golang-jwt/jwt](https://github.com/golang-jwt/jwt) package. Should work across virtually all environments, on or off of Google's Cloud Platform.

## Getting Started

Please read the documentation at [https://pkg.go.dev/github.com/someone1/gcp-jwt-go/v2](https://pkg.go.dev/github.com/someone1/gcp-jwt-go/v2)

## Performance

There are many tradeoffs which the various signing mechanism available from Google's Cloud Platform. Below you will find a chart of performance for the different algorithms and APIs. Here are some overall takeaways:

- **AppEngine:** The fastest option available though limited in that it can only sign on behalf of the default service account and only runs on AppEngine Standard. Keys are auto-rotated, limited to RS256.
- **IAM Api:** Flexible in that you can sign on behalf of various service accounts (see Tips below), runs on any platform, keys are auto-rotated, but is the slowest option available and limited to RS256.
- **Cloud KMS:** Fast (_enough?_), highly flexible (come up with your own keys/usage/algorithm/etc.), runs on any platform, however key rotation is left to the user.

_**note:** all latency numbers are ordered as (50th %ile, 95th %ile, 99th %ile). Tests were run on a F1 AppEngine Standard instance in the us-central region. All Cloud KMS keys are set to global._

#### Signing Performance

| Signer          | Signature Length | Sign Latency                    | Samples |
| --------------- | ---------------- | ------------------------------- | ------- |
| AppEngine       | 342              | 9.14 ms, 17.56 ms, 79.15 ms     | 100     |
| IAMBlob         | 342              | 198.37 ms, 217.42 ms, 244.91 ms | 100     |
| IAMJWT          | 342              | 109.03 ms, 208.46 ms, 212.65 ms | 100     |
| KMSES256        | 86               | 31.57 ms, 44.09 ms, 44.54 ms    | 50      |
| KMSES384        | 128              | 34.67 ms, 51.16 ms, 59.48 ms    | 50      |
| KMSPS256 (2048) | 342              | 38.20 ms, 57.75 ms, 70.47 ms    | 50      |
| KMSPS256 (3072) | 512              | 42.77 ms, 58.24 ms, 62.86 ms    | 50      |
| KMSPS256 (4096) | 683              | 52.02 ms, 64.70 ms, 92.15 ms    | 50      |
| KMSRS256 (2048) | 342              | 37.94 ms, 61.94 ms, 77.33 ms    | 50      |
| KMSRS256 (3072) | 512              | 39.85 ms, 50.52 ms, 56.17 ms    | 50      |
| KMSRS256 (4096) | 683              | 50.19 ms, 68.48 ms, 86.02 ms    | 50      |

#### Verify Performance

| Verifier               | Cache    | Verify Latency                  | Samples |
| ---------------------- | -------- | ------------------------------- | ------- |
| AppEngineVerify        | false    | 6.42 ms, 9.33 ms, 10.86 ms      | 50      |
| AppEngineVerify        | true     | 0.87 ms, 1.05 ms, 25.03 ms      | 50      |
| IAMVerify              | false    | 12.52 ms, 21.45 ms, 30.63 ms    | 100     |
| IAMVerify              | true     | 0.86 ms, 1.01 ms, 53.19 ms      | 100     |
| KMSVerify (2048-PS256) | _always_ | 0.88 ms, 1.01 ms, 32.15 ms      | 50      |
| KMSVerify (2048-RS256) | _always_ | 0.93 ms, 1.11 ms, 19.96 ms      | 50      |
| KMSVerify (3072-PS256) | _always_ | 1.53 ms, 1.71 ms, 43.35 ms      | 50      |
| KMSVerify (3072-RS256) | _always_ | 1.61 ms, 2.11 ms, 42.39 ms      | 50      |
| KMSVerify (4096-PS256) | _always_ | 2.94 ms, 66.88 ms, 71.60 ms     | 50      |
| KMSVerify (4096-RS256) | _always_ | 2.70 ms, 55.25 ms, 72.34 ms     | 50      |
| KMSVerify (ES256)      | _always_ | 0.15 ms, 0.20 ms, 0.29 ms       | 50      |
| KMSVerify (ES384)      | _always_ | 181.21 ms, 193.25 ms, 195.08 ms | 50      |

_Where cache=false is where we get the most value from these numbers as it shows the time to fetch/parse public certificates, the other cases are just the time to use a cached certificate to validate the JWT._

## Tips

- If using the IAM API - create a separate service account to sign on behalf of for your projects unless you NEED to use your default service account (e.g. the AppEngine service account). This way you can limit the scope of access for any leaked credentials. You'll have to grant the `roles/iam.serviceAccountTokenCreator` role to any user/group/serviceaccount you want to be able to sign on behalf of the new service account (resource: `projects/-/serviceAccounts/<serviceaccount>`). For example, create an api-signer service account, do NOT furnish any keys for it, [grant](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/setIamPolicy) your AppEngine/GCE/etc. default service account the proper role for that serviceAccount, and use the api-signer@... service account address in your configuration.
  For example, to setup to use an AppEngine service account to sign on behalf of a service account api-signer (be sure to `export PROJECT_ID=your-project-id` before executing the below):

```bash
# First, create the api-signer service account
gcloud beta iam service-accounts create api-signer --description="Tokens must be signed by this service account in order to authenticate to the API" --display-name="API Signer" --project=$PROJECT_ID

# Grant the AppEngine service account proper permissions to sign tokens on behalf of the service account we just created
gcloud beta iam service-accounts add-iam-policy-binding  api-signer@$PROJECT_ID.iam.gserviceaccount.com --member=serviceAccount:$PROJECT_ID@appspot.gserviceaccount.com --role=roles/iam.serviceAccountTokenCreator --project=$PROJECT_ID
```

Understand this process by reading [this article](https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials).

- If using outside of GCP, be sure to put credentials for an account that can access the service account for signing tokens in a well known location:
  1. A JSON file whose path is specified by the GOOGLE_APPLICATION_CREDENTIALS environment variable.
  2. A JSON file in a location known to the gcloud command-line tool. On Windows, this is %APPDATA%/gcloud/application_default_credentials.json. On other systems, \$HOME/.config/gcloud/application_default_credentials.json.
