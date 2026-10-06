# Hosting WordPress (PHP-FPM) with Vajra

Vajra speaks FastCGI to PHP-FPM, so any PHP application runs behind it. This guide covers WordPress on Debian/Ubuntu;
other distributions differ only in package and socket names.

## 1. Install

```bash
sudo apt install php-fpm php-mysql php-curl php-gd php-mbstring php-xml php-zip mariadb-server
sudo mkdir -p /var/www/html && cd /var/www/html
sudo curl -LO https://wordpress.org/latest.tar.gz
sudo tar xzf latest.tar.gz --strip-components=1 && sudo rm latest.tar.gz
sudo chown -R www-data:www-data /var/www/html
```

## 2. PHP-FPM pool

`/etc/php/8.3/fpm/pool.d/www.conf` (the defaults already listen on `/run/php/php8.3-fpm.sock`). Make the Vajra user
able to reach the socket:

```ini
listen = /run/php/php8.3-fpm.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 20          ; the real concurrency limit; size it by RAM / ~60 MB per worker
```
Run Vajra as `www-data` (edit `deploy/vajra.service`: `User=www-data`) or add its user to the socket's group.

`/etc/php/8.3/fpm/php.ini`:
```ini
cgi.fix_pathinfo = 0
upload_max_filesize = 64M
post_max_size = 64M
max_execution_time = 30
```
`sudo systemctl restart php8.3-fpm`

## 3. Vajra

```toml
[server]
listen = "0.0.0.0:80"

[limits]
max_body_bytes = 67108864     # >= post_max_size; request bodies are buffered in memory

[static]
root = "/var/www/html"

[php]
upstream = "unix:/run/php/php8.3-fpm.sock"
timeout_secs = 60             # per I/O operation; >= max_execution_time

[logging]
access_log = "/var/log/vajra/access.log"
```
HTTPS and HTTP/3: add `[tls]` and `[quic]` as in the user guide, then set *Settings -> General* URLs to `https://`.
Vajra sets `HTTPS=on` and `SERVER_PORT` for PHP on TLS listeners, which is what WordPress uses to detect SSL.

Check and start:
```bash
vajra --config vajra.toml --check      # prints "php (fastcgi) -> 1 upstream(s), root ..., front controller /index.php"
vajra --config vajra.toml
```
Open the site and finish the WordPress installer. Pretty permalinks work out of the box (the front controller handles any
path that is not a file); `/index.php/2026/10/post` style (PATH_INFO) permalinks work too.

## What Vajra does for you

| request | result |
|---|---|
| `/wp-login.php`, `/wp-admin/admin-ajax.php`, `/xmlrpc.php` | executed by PHP-FPM |
| `/wp-admin/`, `/` | directory index script runs |
| `/2026/10/hello-world/`, `/wp-json/wp/v2/posts` | no such file -> `/index.php` with the original `REQUEST_URI` |
| `/wp-content/themes/x/style.css`, images | served directly by Vajra (zero-copy, per-core file cache) |
| `/wp-content/uploads/anything.php` | **404**: uploads never execute PHP (`deny_exec`) |
| `/missing.php`, `/style.css/x.php` | 404: never a static file, never the front controller |
| `/.git/config`, `/.env` | 404 |

## Behind a CDN or load balancer

Client `X-Forwarded-*` headers are deliberately **not** passed to PHP (they would be spoofable). `REMOTE_ADDR` is the
TCP peer. If Vajra sits behind a trusted proxy, restore client IPs in WordPress with a must-use plugin that reads the
header you trust, or terminate the CDN-facing connection with a trusted address list there.

## Several PHP-FPM servers

```toml
[php]
upstreams = ["10.0.0.21:9000", "10.0.0.22:9000"]
script_root = "/var/www/html"      # path as PHP-FPM sees it, if it differs
balance = "least_conn"
```
Passive health and failover work as for proxies: a GET/HEAD that fails before any response byte is retried on another
server; POST is never replayed. Every FPM host needs the same files (shared storage); Vajra checks that scripts exist
under *its own* `[static] root`, so mount the code there too.

## Limits to know about

* Requests and responses are buffered in memory (`max_body_bytes`, `max_proxy_response_bytes`), so very large uploads or
  downloads through PHP cost RAM per concurrent request; serve large downloads as static files instead.
* One FastCGI connection per request (no `KEEP_CONN`): fine over Unix sockets, a little slower over remote TCP.
* No `fastcgi_cache` equivalent yet; put a CDN or WordPress page-cache plugin in front for heavy read traffic.
* Chunked request bodies to PHP are refused with 411 (browsers and curl send `Content-Length`).
* `timeout_secs` is per I/O operation, not a total deadline; PHP's `max_execution_time` is the real cap.
* HTTP/2 and HTTP/3 clients are served PHP too, but one proxied request per HTTP/2 connection runs at a time.

## Troubleshooting

| symptom | check |
|---|---|
| 502 on every PHP page | socket path/permissions (`ls -l /run/php/`), FPM running, Vajra user in the socket group |
| 504 | slow script or `timeout_secs` below `max_execution_time` |
| 404 for `/index.php` | `[static] root` is not the WordPress directory, or file not readable by Vajra |
| redirect loop after enabling HTTPS | URLs in *Settings -> General* still `http://`; make sure the request arrived on the `[tls]` listener |
| uploads fail with 413 | raise `[limits] max_body_bytes` (and PHP's `post_max_size`) |
| PHP warnings missing | they go to Vajra's stderr (`journalctl -u vajra`) and FPM's own log |

`scripts/php-smoke.sh` runs a real PHP-FPM and Vajra together and checks PATH_INFO, the front controller, POST bodies,
status codes, multiple cookies, upload blocking and a 3 MB upload.
