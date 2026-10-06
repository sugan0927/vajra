# Tuning and profiling

Nothing here is measured on your hardware; treat each item as a hypothesis to test with `bench/run.sh`.

## System
* **CPU**: `cpupower frequency-set -g performance`; disable deep C-states for latency tests; keep SMT siblings free
  (one worker per physical core is a good start: `--workers = physical cores`).
* **NIC**: pin IRQs to the same cores as the workers (`irqbalance` off; `/proc/irq/*/smp_affinity`), enable RSS with one
  queue per worker, `ethtool -K <if> gro on`; for HTTP/3 also `rx-udp-gro-forwarding`/UDP GRO if available.
* **Sockets**: `net.core.somaxconn=65535`, `net.ipv4.tcp_max_syn_backlog=65535`, `net.core.rmem_max`/`wmem_max=8388608`
  (Vajra asks for 4 MiB UDP buffers and silently gets less if the cap is lower), `net.ipv4.ip_local_port_range` wide for proxies.
* **Limits**: `LimitNOFILE=1048576`; io_uring memory is accounted against `RLIMIT_MEMLOCK` on kernels < 5.12.
* **Kernel**: 6.1+ recommended; check `sysctl kernel.io_uring_disabled` (must be 0).

## Vajra knobs
| knob | effect |
|---|---|
| `workers` / `pin` | one per core; pinning avoids migrations and keeps rings cache-local |
| `ring_entries` | larger rings batch more submissions per syscall; 1024 is plenty below ~100k connections per worker |
| `read_buf_size` | bigger buffers mean fewer reads for large uploads, more memory per idle connection |
| `max_conns` | memory bound: roughly `read_buf_size` + a few hundred bytes of connection state each |
| `static.cache_ttl_secs` | how long an open file descriptor is trusted; larger = fewer `open` calls, slower change visibility |
| `[limits] max_body_bytes` | PHP uploads are buffered in memory before the request starts: set it to your largest upload and keep `upload_max_filesize`/`post_max_size` in php.ini at least as large |
| `[php] timeout_secs` | per I/O operation (connect, send, each receive); keep it at or above `max_execution_time` or slow pages become 504 |
| PHP-FPM `pm.max_children` | the real concurrency limit of PHP; Vajra opens one connection per request, so excess requests queue in FPM's listen backlog |
| proxy `max_fails`/`fail_timeout_secs` | trade fast ejection against flapping |

## Ideas that need measurement before adoption
1. **Registered files and buffers** (`IORING_REGISTER_FILES/BUFFERS`) to cut per-op fd lookups and page pinning.
2. **`SQPOLL`** for latency-critical deployments with spare cores (burns a core per ring).
3. **kTLS** (`TLS_TX`) so TLS file bodies can use `splice`/`sendfile` again.
4. **UDP GSO/GRO** for HTTP/3: batch segments with `UDP_SEGMENT`; the engine already supports multi-datagram transmits.
5. **Connection-ID-aware steering** (eBPF `SO_REUSEPORT` program) to re-enable QUIC migration.
6. **Shared TLS ticket keys** distributed over the control channel so resumption works across cores.
7. **Arena-backed request path**: replace per-request `Vec`s in the parser/response writer with bump allocation reset per batch.
8. **Streaming proxy bodies** instead of buffering (needs per-direction flow control like the WebSocket tunnel).
9. **Async file open** (`IORING_OP_OPENAT`/`STATX`) to remove the synchronous open on cache misses.

## Profiling workflow
```
cargo build --release                       # debug=1 is on, so symbols are present
perf record -F 999 -g --call-graph dwarf -p $(pidof vajra) -- sleep 20
perf report --no-children                   # or: cargo flamegraph --pid ...
perf stat -e cycles,instructions,cache-misses,context-switches -p $(pidof vajra) -- sleep 20
```
Look for: syscalls per request (`strace -c -f -p` — the loop should show almost only `io_uring_enter`),
context switches (should be near zero with pinning), `memcpy` share in TLS paths, allocator frames in the parser.
`bpftrace -e 'tracepoint:io_uring:io_uring_complete { @[args->opcode] = count(); }'` shows the operation mix.

## Allocator note
The slab pool covers receive buffers only. Everything else uses the system allocator. A per-thread allocator
(`mimalloc`/`jemalloc` with per-thread arenas) is a one-line change in `main.rs` (`#[global_allocator]`) worth benchmarking
before writing more custom allocation code.
