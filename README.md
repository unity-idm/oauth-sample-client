# OAuth Sample Client

A standalone OAuth Client. Implemented with the help of Spring Boot using Nimbus OAuth 2.0 / OIDC SDK (no Spring Security OAuth client).

Supports PKCE, confidential client authentication, DPoP and UserInfo retrieval.

## Configuration

The values pre-filled into the form on the start screen - endpoint URLs, client id and credential, scope and
the flow options - are configurable, so that a frequently used AS does not have to be typed in over and over.
They are only defaults: each one can still be changed in the UI before starting the flow.

The shipped defaults are in `src/main/resources/application.properties`, under the `oauth.client.defaults.*`
prefix. To override them locally, copy the example file:

```
cp client-defaults.properties.example client-defaults.properties
```

`client-defaults.properties` is git ignored, so your own AS URLs and credentials stay out of the repository.
It is optional and picked up from the working directory the app is started in (the project root when running
with `mvn spring-boot:run`). See `client-defaults.properties.example` for the full list of settings with
comments. Any other Spring Boot property, e.g. `server.port`, can be set there as well.

One setting is not a form field: `oauth.client.defaults.redirect-uri`. Left empty, the redirect URI is
computed from the incoming request, honoring the `X-Forwarded-Proto` and `X-Forwarded-Host` headers. Set it
only when that autodetection can not work, e.g. behind a proxy which does not send those headers.

## DPoP

DPoP (RFC 9449) is enabled with a checkbox on the initial screen. When enabled:

* A **fresh proof-of-possession key is generated for each authentication attempt**, of the selected kind:
  * `EC P-256` signing with `ES256`
  * `RSA 2048` signing with `RS256`
  * `OKP Ed25519` signing with `EdDSA`
* A DPoP proof is attached to the **token request** and, if a UserInfo endpoint is configured, to the
  **UserInfo request** (there with the `ath` claim binding the proof to the access token).
* **Server provided nonces are handled at both endpoints.** A server which requires a nonce answers the first
  request with `use_dpop_nonce` (HTTP 400 with a JSON error at the token endpoint, HTTP 401 with a
  `WWW-Authenticate: DPoP` header at the UserInfo endpoint) and a `DPoP-Nonce` header. The request is then
  retried once with a freshly signed proof carrying that nonce.
* Optionally the `dpop_jkt` parameter (RFC 9449 sec. 10) is sent with the authorization request, binding the
  authorization code to the DPoP key.
* The access token is presented to the UserInfo endpoint with the `DPoP` scheme only if the AS actually
  returned it with `token_type: DPoP`; otherwise it is presented as a bearer token, and the result screen says so.

The result screen summarizes whether DPoP was used, whether a server provided nonce was needed at each
endpoint, the public key with its `jkt` thumbprint, and the decoded DPoP proofs which were sent.

## Build

```
mvn package
```

## Run

Run from Maven
```
mvn -pl oauth-sample-client spring-boot:run -DskipTests -Dgpg.skip=true
```

App listens on port 8085 by default. Open:
```
http://localhost:8085/
```
