# Benchmark methodology

`bench/run.sh` compares Vajra and nginx on one machine with identical content. **No results are published in this
repository** because none were measured; produce your own and report the environment file it writes.

## What is compared
| scenario | what it exercises |
|---|---|
| `static-small` | request parsing, routing, header generation, `splice` of a 14-byte file |
| `static-1k` | same with a 1 KiB body |
| `static-1m` | zero-copy throughput (`splice` vs `sendfile`) |
| `proxy` | upstream pooling and response relay to a trivial nginx upstream |
| vegeta fixed rate | latency distribution at a constant request rate (avoids coordinated omission) |
| `ws_load.py` | WebSocket echo round trips through the tunnel |

## Rules for a fair run
1. Separate CPUs for servers and load generator (the script pins them); same worker count for both servers.
2. Quiet machine, performance governor, warm up (run twice, discard the first), at least 20 s per scenario.
3. Loopback measures software overhead only; for NIC/driver effects use two machines and a real network.
4. Equalise features: access log off in both, no TLS unless comparing TLS (then the same cipher suites), keep-alive on.
5. Report p50/p99/p99.9, errors, CPU utilisation per server (`pidstat`), and the exact versions.
6. Do not compare HTTP/3 against nginx numbers from a different QUIC stack without saying so.

## Expectations (hypotheses, not claims)
* Small static responses: dominated by syscalls per request; io_uring batching should help most at high connection counts.
* 1 MiB files: both approaches are memory-bandwidth bound; differences will be small.
* Proxy: nginx is mature here; Vajra buffers whole bodies, so large responses will not favour it.
* TLS: Vajra copies plaintext through rustls without kTLS; expect a gap versus OpenSSL+kTLS+sendfile on large files.
