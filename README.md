# gcp-jwt-go [![GoDoc](https://godoc.org/github.com/someone1/gcp-jwt-go?status.svg)](https://godoc.org/github.com/someone1/gcp-jwt-go) [![Go Report Card](https://goreportcard.com/badge/github.com/someone1/gcp-jwt-go)](https://goreportcard.com/report/github.com/someone1/gcp-jwt-go) [![Build Status](https://travis-ci.org/someone1/gcp-jwt-go.svg)](https://travis-ci.org/someone1/gcp-jwt-go) [![Coverage Status](https://coveralls.io/repos/github/someone1/gcp-jwt-go/badge.svg)](https://coveralls.io/github/someone1/gcp-jwt-go)

Google Cloud Platform (Cloud KMS, IAM API, & AppEngine App Identity API) jwt-go implementations

## New with v2:

Google Cloud KMS [now supports signatures](https://cloud.google.com/kms/docs/create-validate-signatures) and support has been added to gcp-jwt-go!

## Breaking Changes with v2

- Package name changed from gcp_jwt to gcpjwt
- Refactoring of code (including exported functions/structs)
- Certificate caching is now opt-in vs opt-out

To continue using the older version, please import as follows: `import "gopkg.in/someone1/gcp-jwt-go.v1"`

### Features

gcp-jwt-go has basic implementations of using [Google Cloud KMS](https://cloud.google.com/kms/docs/create-validate-signatures), Google IAM API (both [signJwt](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signJwt) and [signBlob](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signBlob)), and the [App Identity API](https://cloud.google.com/appengine/docs/go/appidentity/) from AppEngine Standard on Google Cloud Platform to sign JWT tokens using the [dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go) package. Should work across virtually all environments, on or off of Google's Cloud Platform.

## Getting Started

Please read the documentation at [https://godoc.org/github.com/someone1/gcp-jwt-go](https://godoc.org/github.com/someone1/gcp-jwt-go)

## Tips

- If using the IAM API - create a separate service account to sign on behalf of for your projects unless you NEED to use your default service account (e.g. the AppEngine service account). This way you can limit the scope of access for any leaked credentials. You'll have to grant the `roles/iam.serviceAccountTokenCreator` role to any user/group/serviceaccount you want to be able to sign on behalf of the new service account (resource: `projects/-/serviceAccounts/<serviceaccount>`). For example, create an api-signer service account, do NOT furnish any keys for it, [grant](https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/setIamPolicy) your AppEngine/GCE/etc. default service account the proper role for that serviceAccount, and use the api-signer@... service account address in your configuration.
- If using outside of GCP, be sure to put credentials for an account that can access the service account for signing tokens in a well known location:
  1. A JSON file whose path is specified by the GOOGLE_APPLICATION_CREDENTIALS environment variable.
  2. A JSON file in a location known to the gcloud command-line tool. On Windows, this is %APPDATA%/gcloud/application_default_credentials.json. On other systems, $HOME/.config/gcloud/application_default_credentials.json.
