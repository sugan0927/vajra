#!/usr/bin/env bash
# Smoke test against a REAL PHP-FPM (the integration tests use a mock).
#   scripts/php-smoke.sh            # needs php-fpm and curl; starts both, checks, cleans up
set -euo pipefail
cd "$(dirname "$0")/.."
FPM=$(command -v php-fpm || command -v php-fpm8.3 || command -v php-fpm8.2 || command -v php-fpm8.4 || true)
[ -n "$FPM" ] || { echo "php-fpm not found (apt install php-fpm)"; exit 2; }
[ -x target/release/vajra ] || cargo build --release

T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$T"' EXIT
mkdir -p "$T/www/wp-content/uploads"
cat > "$T/www/index.php" <<'PHP'
<?php
header('X-Test: yes');
setcookie('a', '1'); setcookie('b', '2');
echo json_encode(['uri' => $_SERVER['REQUEST_URI'], 'script' => $_SERVER['SCRIPT_NAME'],
  'path_info' => $_SERVER['PATH_INFO'] ?? null, 'method' => $_SERVER['REQUEST_METHOD'],
  'post' => $_POST, 'get' => $_GET, 'remote' => $_SERVER['REMOTE_ADDR']]);
PHP
echo '<?php http_response_code(418); echo "teapot";' > "$T/www/teapot.php"
echo '<?php echo "pwned";' > "$T/www/wp-content/uploads/evil.php"
echo 'body{}' > "$T/www/style.css"

cat > "$T/fpm.conf" <<CONF
[global]
daemonize = no
error_log = $T/fpm.log
[www]
listen = $T/fpm.sock
pm = static
pm.max_children = 4
clear_env = no
CONF
"$FPM" -y "$T/fpm.conf" -F &
cat > "$T/vajra.toml" <<CONF
[server]
listen = "127.0.0.1:18080"
workers = 1
pin = false
[limits]
max_body_bytes = 8388608
[static]
root = "$T/www"
[php]
upstream = "unix:$T/fpm.sock"
CONF
./target/release/vajra --config "$T/vajra.toml" &
for _ in $(seq 50); do curl -fs http://127.0.0.1:18080/health >/dev/null 2>&1 && break; sleep 0.1; done

B=http://127.0.0.1:18080
ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; exit 1; }
curl -fs "$B/index.php/a/b?x=1" | grep -q '"path_info":"\\/a\\/b"' && ok "path_info" || bad "path_info"
curl -fs "$B/2026/10/pretty?p=1" | grep -q '"script":"\\/index.php"' && ok "front controller" || bad "front controller"
curl -fs -d 'u=1&v=2' "$B/" | grep -q '"post":{"u":"1","v":"2"}' && ok "POST" || bad "POST"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$B/teapot.php")" = 418 ] && ok "status" || bad "status"
[ "$(curl -si "$B/" | grep -ic '^set-cookie:')" = 2 ] && ok "two cookies" || bad "two cookies"
curl -si "$B/" | grep -qi '^x-test: yes' && ok "headers" || bad "headers"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$B/wp-content/uploads/evil.php")" = 404 ] && ok "uploads blocked" || bad "uploads blocked"
[ "$(curl -s "$B/style.css")" = 'body{}' ] && ok "static" || bad "static"
head -c 3000000 /dev/zero > "$T/big"; [ "$(curl -s -o /dev/null -w '%{http_code}' --data-binary @"$T/big" "$B/")" = 200 ] && ok "3 MB upload" || bad "upload"
echo "all good"
