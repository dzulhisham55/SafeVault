#!/usr/bin/env bash
# Live smoke test: drives the real server over HTTP the way a browser would.
set -u

cd "$(dirname "$0")/.." || exit 1
export PATH="$HOME/.dotnet:$PATH"
export DOTNET_NOLOGO=1
export ASPNETCORE_ENVIRONMENT=Development
export SafeVault__DatabasePath=/tmp/safevault-smoke.db

rm -f /tmp/safevault-smoke.db*
JAR=/tmp/safevault-smoke-cookies.txt
rm -f "$JAR"

dotnet run --project SafeVault.Web --no-build --no-launch-profile \
    --urls http://127.0.0.1:5081 > /tmp/safevault-smoke.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT

for _ in $(seq 1 60); do
    curl -s -o /dev/null http://127.0.0.1:5081/Account/Login && break
    sleep 0.5
done

BASE=http://127.0.0.1:5081
PASS="ChangeMe!2026#Root"

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "root_anon=$(code "$BASE/")"
echo "login_page=$(code "$BASE/Account/Login")"
echo "vault_anon=$(code "$BASE/Vault")"
echo "api_anon=$(code "$BASE/api/items")"

curl -s -c "$JAR" "$BASE/Account/Login" -o /tmp/safevault-login.html
TOKEN=$(grep -o 'name="__RequestVerificationToken"[^>]*value="[^"]*"' /tmp/safevault-login.html | sed 's/.*value="//; s/"$//' | head -n1)

echo "login_admin=$(curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}' -b "$JAR" -c "$JAR" \
    --data-urlencode "__RequestVerificationToken=$TOKEN" \
    --data-urlencode "Input.Username=admin" \
    --data-urlencode "Input.Password=$PASS" \
    "$BASE/Account/Login")"

curl -s -b "$JAR" -c "$JAR" "$BASE/Vault" -o /tmp/safevault-vault.html
TOKEN=$(grep -o 'name="__RequestVerificationToken"[^>]*value="[^"]*"' /tmp/safevault-vault.html | sed 's/.*value="//; s/"$//' | head -n1)

echo "create_payload=$(curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}' -b "$JAR" \
    --data-urlencode "__RequestVerificationToken=$TOKEN" \
    --data-urlencode 'Title=Smoke <script>alert(1)</script>' \
    --data-urlencode 'Body=<img src=x onerror=alert(1)> stored payload' \
    "$BASE/Vault?handler=Create")"

curl -s -b "$JAR" "$BASE/Vault/Detail?id=1" -o /tmp/safevault-detail.html
echo "detail_encoded_script=$(grep -c '&lt;script&gt;' /tmp/safevault-detail.html)"
echo "detail_raw_script=$(grep -c '<script' /tmp/safevault-detail.html)"
echo "list_marks_search=$(curl -s -b "$JAR" "$BASE/Vault?q=Smoke" | grep -c '<mark>Smoke</mark>')"

echo "api_item=$(code -b "$JAR" "$BASE/api/items/1")"
echo "api_item_type=$(curl -s -o /dev/null -w '%{content_type}' -b "$JAR" "$BASE/api/items/1")"
echo "raw_content_type=$(curl -s -o /dev/null -w '%{content_type}' -b "$JAR" "$BASE/api/items/1/content")"
echo "raw_body=$(curl -s -b "$JAR" "$BASE/api/items/1/content")"

echo "admin_page=$(code -b "$JAR" "$BASE/Admin")"
echo "csp_header=$(curl -s -D - -o /dev/null "$BASE/Account/Login" | grep -ci 'content-security-policy')"
echo "nosniff_header=$(curl -s -D - -o /dev/null "$BASE/Account/Login" | grep -ci 'x-content-type-options: nosniff')"

# Lockout: five bad passwords, then the correct one must still be refused.
for _ in $(seq 1 5); do
    curl -s -o /dev/null -b "$JAR" -c "$JAR" \
        --data-urlencode "__RequestVerificationToken=$TOKEN" \
        --data-urlencode "Input.Username=admin" \
        --data-urlencode "Input.Password=wrong-password" \
        "$BASE/Account/Login"
done
echo "lockout_message=$(curl -s -b "$JAR" --data-urlencode "__RequestVerificationToken=$TOKEN" \
    --data-urlencode "Input.Username=admin" --data-urlencode "Input.Password=$PASS" \
    "$BASE/Account/Login" | grep -c 'Too many failed attempts')"

echo "server_errors=$(grep -ci 'fail:\|unhandled exception' /tmp/safevault-smoke.log)"
