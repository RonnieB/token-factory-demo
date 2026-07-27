#!/usr/bin/env bash
# Builds the project, runs the unit tests, then starts the server and exercises the full
# flow with nothing but a curl cookie jar as the client:
#   1. issue a token (10s TTL) + a refresh token
#   2. call the protected endpoint while the token is fresh
#   3. wait for the token to expire
#   4. call again: the server answers 302 -> /refresh, mints a new token, 302 -> /me
set -euo pipefail
cd "$(dirname "$0")"

PORT=8080
BASE="http://localhost:$PORT"
JAR="curl-cookies.txt"
BUILD_LOG="build.log"

echo "==> Building and running unit tests"
mvn -q clean package | tee "$BUILD_LOG"

echo
echo "==> The tests printed the token before and after encryption (signed claims decoded):"
awk '/--- JWT before encryption/{f=1} f{print} /--- JWT after encryption/{getline; print; exit}' "$BUILD_LOG"

echo "==> Starting server on port $PORT"
java -jar target/token-factory-demo-1.0.0.jar >server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true; rm -f $JAR $BUILD_LOG' EXIT

# A 302 to /refresh from the protected endpoint means the server is up and secured
for _ in $(seq 30); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/me")" = "302" ] && break
  sleep 1
done

echo "==> Issuing a token for user 'alice' (cookies saved to the jar)"
curl -s -c "$JAR" -X POST "$BASE/tokens?user=alice"
echo

echo "==> The access token is now a nested JWT (signed then encrypted), so it is opaque to the client"
TOKEN=$(grep access_token "$JAR" | awk '{print $NF}')
echo "Compact parts: $(echo "$TOKEN" | awk -F. '{print NF}') (a JWE has 5; a plain signed JWT would have 3)"
echo "Only the server, holding the encryption private key, can read it — the client just carries it."

echo "==> Calling /me while the token is fresh (the server decrypts and verifies it)"
curl -s -b "$JAR" "$BASE/me"; echo

echo "==> Showing the raw 302 the server sends once the token has expired"
sleep 11
curl -s -o /dev/null -w 'GET /me -> HTTP %{http_code}, Location: %{redirect_url}\n' -b "$JAR" "$BASE/me"

echo "==> Calling /me again with -L so curl follows the refresh redirect automatically"
curl -s -L -b "$JAR" -c "$JAR" "$BASE/me"; echo

echo "==> All checks passed"
