# Fuzzing Vajra

Targets (libFuzzer via [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)):

| target              | covers |
|---------------------|--------|
| `h1_request`        | HTTP/1.1 parsing, pipelining, routing, proxy request building, cache lookup |
| `h2_frames`         | HTTP/2 frames, HPACK, flow control, abuse limits, response framing |
| `h3_request`        | HTTP/3 request streams: frame order, QPACK field sections, header validation |
| `h3_uni`            | HTTP/3 control / QPACK / unknown unidirectional streams |
| `qpack_block`       | QPACK decoder alone (static table, literals, Huffman) |
| `upstream_response` | upstream response heads, framing choice, chunked decoding |
| `config_toml`       | configuration parsing/validation |
| `cache_headers`     | cacheability and request-bypass rules |
| `static_path`       | path mapping: nothing outside the document root may be served |
| `fcgi_response`     | FastCGI record stream, CGI header block, CGI->HTTP rewrite, then the proxy response parser |
| `php_resolve`       | PHP script / PATH_INFO / front-controller resolution (no traversal, no hidden files) |

```
cargo install cargo-fuzz            # needs nightly
cd fuzz
cargo +nightly fuzz run h1_request -- -dict=dictionaries/http.dict -max_total_time=600
cargo +nightly fuzz run h3_request -- -max_total_time=600
cargo +nightly fuzz run h2_frames  -- -max_total_time=600
```

Seed corpora live in `corpus/`; crashes land in `artifacts/`. A crash is a bug: parsers
must return errors, never panic (the release profile aborts on panic). Reproduce with
`cargo +nightly fuzz run <target> artifacts/<target>/crash-...`, then add a regression
test to `tests/robustness.rs`.

Not fuzzed here: the QUIC transport itself (`quinn-proto` has its own fuzzing) and the
io_uring glue, which is covered by the integration tests instead. For those, run the
server under `AddressSanitizer`/`ThreadSanitizer` nightly builds while driving
`tests/*` and the benchmark load.

The same entry points are exercised without cargo-fuzz by the deterministic
mutation tests in `tests/robustness.rs`, which run in every `cargo test`.
