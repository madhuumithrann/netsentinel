# NetSentinel security design

NetSentinel parses files that may be broken, oversized or deliberately hostile, and those
files can contain sensitive traffic. This document lists what we defend against, how, and
which automated test proves each defence. Known limitations are listed at the end.

## Threat model

| Asset / risk | Attacker capability | Defence | Test |
|---|---|---|---|
| Server memory | Upload a tiny file whose record header claims a 4 GB packet. The original prototype allocated about 4.3 GB from a 140-byte file. | Our own container reader (`app/pcapio.py`) checks every length field against the remaining file size and a per-record limit (`max_record_bytes`, 256 KiB) **before** reading. Oversized blocks are skipped with `seek`, never loaded. | `test_huge_record_length_does_not_allocate`, `test_pcapng_huge_block_length_does_not_allocate`, `test_oversized_record_is_skipped_not_loaded` |
| Server disk / memory | Upload a multi-GB body | ASGI middleware `BodySizeLimit` rejects bodies above the limit while they stream in (Content-Length check plus a running byte count), before multipart parsing finishes. Default limit is 100 MB. | `test_api_upload_size_limit_rejects_before_reading` |
| CPU / availability | Upload a capture designed to be slow, or many uploads at once | Packet limit (300,000), analysis deadline (90 s, partial results with a warning), at most 2 concurrent analyses (HTTP 429 beyond that). Analysis runs in a worker thread, so the server stays responsive. | `test_packet_limit_stops_early` |
| Parser crash | Malformed, truncated or fuzzed frames | Every header field is bounds-checked. A frame that cannot be decoded is marked `malformed` and counted, and decoding continues. A failing detector is isolated and reported, and the others still run. | `test_fuzzed_captures_never_crash` (150 mutated captures), `test_dns_decoder_random_garbage_never_raises` (2,000 mutated DNS messages), `test_truncated_headers_marked_malformed` |
| Parser hang | DNS compression pointer loops | `decode_dns` only follows pointers that point strictly backwards and caps names at 255 bytes. | `test_dns_pointer_loop_is_rejected_quickly`, `test_dns_overlong_and_truncated_names_rejected` |
| File-type confusion | A non-capture file renamed to `.pcap` | The format is identified from the magic number, never from the extension. Non-captures get HTTP 422 with a plain message. | `test_non_capture_rejected`, `test_api_rejects_bad_input_without_leaking_files` |
| Data retention | Uploaded captures left on disk | NetSentinel writes no copy of an upload. It analyses Starlette's spooled temporary file, which is deleted when the request ends. The original prototype leaked uploads in `%TEMP%` on Windows because Scapy kept a file handle open. | `test_api_rejects_bad_input_without_leaking_files` |
| Data exposure | Passwords or message contents inside captured payloads | Packet payload bytes are never stored in `PacketRecord` and never returned by the API or shown in the UI. Only header metadata appears as evidence. | `test_no_payload_bytes_in_response` |
| Log / UI injection | Hostile DNS names or file names with control characters or HTML | Capture-derived strings are reduced to printable ASCII and length-capped. File names are reduced to a safe base name (no path, no `<>`). The React UI renders everything as text, with no `dangerouslySetInnerHTML`. | `test_names_are_sanitised`, `test_api_filename_is_sanitised` |
| Information leakage in errors | Trigger exceptions to learn paths or library details | `CaptureError` messages are written for users. Unexpected errors return a generic message with a random error id, and the server log records only the exception type, never paths or packet text. | `test_api_rejects_bad_input_without_leaking_files` |
| Path traversal | `POST /api/samples/../../etc/passwd/analyze` | Only ids listed in `samples/manifest.json` are accepted, and the resolved path must stay inside `samples/`. | `test_api_sample_endpoint_rejects_unknown_and_traversal` |
| Cross-site use of the local API | A malicious web page calling `http://localhost:8000` | CORS lets only `http://localhost:*` and `http://127.0.0.1:*` read responses. The dev server binds to `127.0.0.1` only (the prototype exposed it on the LAN via `--host 0.0.0.0`). Security headers: `nosniff`, `no-referrer`, `no-store`, `X-Frame-Options: DENY`. | `test_api_cors_only_local_origins` |
| Secrets | Credentials committed to the repository | The application has no credentials, keys or tokens to hide. Limits are configured with optional environment variables. `.env*` files are git-ignored. | - |
| Network side effects | The tool sends traffic | Analysis is offline only. NetSentinel never opens a capture interface or sends packets. Synthetic samples are built with Scapy and written to files with `wrpcap`. | - |
| Third-party exposure | The UI contacting outside services | The UI uses a system font stack and no CDN or analytics, so it works without an internet connection. | - |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `NETSENTINEL_MAX_UPLOAD_MB` | 100 | Largest accepted upload |
| `NETSENTINEL_MAX_PACKETS` | 300000 | Packets analysed before stopping, with a warning |
| `NETSENTINEL_MAX_SECONDS` | 90 | Analysis deadline, after which partial results are returned with a warning |
| `NETSENTINEL_MAX_CONCURRENT` | 2 | Simultaneous analyses (HTTP 429 beyond this) |

## Known limitations (honest list)

- **No authentication.** The API is designed to run on the analyst's own machine (bound to
  localhost). Do not expose it on a shared network without adding authentication and TLS in
  front of it.
- **Partial-time limit.** The deadline is checked between packets and between detectors, so
  one detector can overrun the limit by the time it takes to finish its current pass.
- **Memory scales with packet count.** About 0.6 KB of metadata is kept per packet (around
  200 MB at the 300,000-packet limit). Lower `NETSENTINEL_MAX_PACKETS` on small machines.
- **DHCP payloads are decoded with Scapy.** Scapy's DHCP decoder is bounded by the frame
  size (at most 256 KiB) and wrapped in exception handling, but it is third-party code.
- **Results are indicators, not proof.** An attack verdict means the traffic matches
  documented attack indicators. Every finding lists its limitations and alternative
  explanations.
