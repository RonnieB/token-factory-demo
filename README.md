# Token Factory Demo

A minimal example of how little code it takes to mint and consume JWTs with Spring Security.

Two pieces:

1. **Token factory** — creates a **signed and encrypted** JWT from nothing but a user name.
2. **Server component** — a protected endpoint that answers with the user name and
   the accounts carried in the token. Spring Security decrypts, verifies the signature,
   and checks expiry before the controller ever runs.

## The token — signed, then encrypted (a nested JWT)

The factory builds the token in two stages:

1. **Sign** the claims with the signing private key, producing a JWS (a normal signed
   JWT — three dot-separated parts whose payload is readable base64).
2. **Encrypt** that whole signed JWT with the encryption public key, producing a JWE
   (five dot-separated parts). This is the "nested JWT" the client receives; its
   contents are opaque.

The claims inside are:

```json
{
  "iss": "token-factory-demo",
  "sub": "alice",
  "clientId": "alice",
  "accounts": [
    { "accountId": "541926" },
    { "accountId": "756487" }
  ],
  "exp": 1784827045,
  "iat": 1784823445
}
```

The `clientId` claim is the user name you asked for. Two accounts are added, each
with a random six-digit `accountId`. The token lives for **10 seconds** (`exp - iat`).

Signing proves who issued the token; encryption keeps its contents secret in transit
and at rest on the client. Two separate RSA key pairs are used — signing and
encryption — which mirrors real deployments where the sender signs and the recipient
decrypts (algorithms: `RS256` for the signature, `RSA-OAEP-256` + `A256GCM` for the
encryption). The unit tests print the token **before and after encryption** — the
signed JWS is decoded into its human-readable header and claims, next to the opaque
JWE it turns into; `./run.sh` surfaces that printout.

## Expiry and refresh

Both tokens are returned as `HttpOnly` cookies so the client resends them automatically:

- **access token** — the 10-second JWT above, read from the `access_token` cookie
  instead of the `Authorization` header.
- **refresh token** — an opaque random string (not a JWT) tied to the user, valid
  for one hour, stored in the `refresh_token` cookie.

When the access token is missing or expired, the protected endpoint does not return
401. Spring Security's `AuthenticationEntryPoint` sends a **302 redirect** to
`/refresh`, which reads the refresh cookie, mints a new access token, and **302s back**
to the original URL. A client that simply follows redirects (a browser, or
`curl -L` with a cookie jar) never has to know any of this happened:

```
GET /me            -> 302 /refresh?redirect=%2Fme   (access token expired)
GET /refresh...    -> 302 /me                        (new access cookie set)
GET /me            -> 200 { "user": ..., "accounts": ... }
```

Each refresh mints a brand-new token, so the random accounts differ after a refresh.
Once the refresh token itself expires, `/refresh` returns 401 and the client must ask
`/tokens` for a new pair.

## Run it

```bash
./run.sh
```

The script builds the project and runs the unit tests (which print the token before
and after encryption), starts the server, issues a token, shows that the access
token is an opaque 5-part JWE, calls the protected endpoint while the token is fresh,
waits 11 seconds for it to expire, shows the raw 302 the server returns, and finally
calls again with `curl -L` so the refresh redirect resolves automatically.

Manually, using a cookie jar as the client:

```bash
mvn spring-boot:run
```

```bash
curl -s -c jar.txt -X POST 'http://localhost:8080/tokens?user=alice'; curl -s -L -b jar.txt -c jar.txt http://localhost:8080/me
```

## Source

| File | Role |
| --- | --- |
| [TokenFactory.java](src/main/java/com/example/tokenfactory/TokenFactory.java) | Signs the claims, then encrypts the result (nested JWT) |
| [RefreshTokenStore.java](src/main/java/com/example/tokenfactory/RefreshTokenStore.java) | Issues and looks up opaque refresh tokens |
| [JwtConfig.java](src/main/java/com/example/tokenfactory/JwtConfig.java) | Signing + encryption key pairs, `JwtEncoder` and a decrypt-then-verify `JwtDecoder` |
| [SecurityConfig.java](src/main/java/com/example/tokenfactory/SecurityConfig.java) | Cookie bearer resolver + 302-on-expiry entry point |
| [Cookies.java](src/main/java/com/example/tokenfactory/Cookies.java) | Reads and writes the access/refresh cookies |
| [TokenController.java](src/main/java/com/example/tokenfactory/TokenController.java) | `POST /tokens` — issues the token pair as cookies |
| [RefreshController.java](src/main/java/com/example/tokenfactory/RefreshController.java) | `GET /refresh` — mints a new token, 302s back |
| [AccountController.java](src/main/java/com/example/tokenfactory/AccountController.java) | `GET /me` — reads the claims from the validated token |

## Not production ready

The RSA key pairs and the refresh-token store all live in memory, so every restart
invalidates all previously issued tokens and a second instance cannot honor the
first one's. The token endpoint is unauthenticated and hands a pair to anyone who
asks — there is no user authentication at all. The cookies are `HttpOnly` but not
`Secure`, and CSRF protection is disabled to keep the demo short. Before this goes
anywhere near a real system: load a real key (keystore or JWKS), put an actual login
in front of the factory, persist refresh tokens, set `Secure`/`SameSite`, and turn
CSRF protection back on.

## Requirements

Java 21+ and Maven 3.9+.
