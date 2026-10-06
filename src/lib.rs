//! Vajra - a thread-per-core, share-nothing web server built on io_uring.
//!
//! Layering (bottom to top):
//! * [`worker`]       - per-core io_uring loop: sockets, TLS records, body streaming, proxy I/O
//! * [`tls`]          - rustls server configuration
//! * [`http`]         - HTTP/1.1 parse + serialise (no I/O)
//! * [`h2`]           - HTTP/2 framing, HPACK, flow control (no I/O)
//! * [`h3`]           - HTTP/3 framing and stateless QPACK (no I/O)
//! * [`quic`]         - per-core QUIC engine (quinn-proto) driving HTTP/3
//! * [`router`]       - protocol-independent request routing
//! * [`static_files`] - safe path mapping, per-core open-file cache
//! * [`proxy`]        - reverse-proxy route table, load balancing, upstream codecs
//! * [`fastcgi`]      - FastCGI (PHP-FPM) records, CGI environment, CGI->HTTP response rewrite
//! * [`php`]          - WordPress-style script/static/front-controller resolution
//! * [`cache`]        - per-core LRU response cache for proxied GETs
//! * [`observe`]      - per-core metrics, access log, Prometheus rendering
//! * [`control`]      - lock-free cross-core command channel (scrape, reload, shutdown)
//! * [`admin`]        - control-plane manager + admin HTTP endpoint
//! * [`arena`], [`config`], [`date`], [`sys`] - supporting pieces

pub mod admin;
pub mod arena;
pub mod cache;
pub mod config;
pub mod control;
pub mod date;
pub mod fastcgi;
pub mod h2;
pub mod h3;
pub mod http;
pub mod observe;
pub mod php;
pub mod proxy;
pub mod quic;
pub mod router;
pub mod static_files;
pub mod sys;
pub mod tls;
pub mod worker;
