# OAuth Sample Client

A standalone OAuth Client. Implemented with the help of Spring Boot using Nimbus OAuth 2.0 / OIDC SDK (no Spring Security OAuth client).

Supports PKCE. Can be 

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