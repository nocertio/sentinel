# TLS discovery coverage

Sentinel records three distinct outcomes: a completed TLS handshake, certificate
bytes collected without completing the handshake, or a protocol detected without
a certificate. These are observations, not authentication of the remote service.
Certificate trust, signatures, key properties and compliance are evaluated by
NoCert's backend parser.

| Service or property | Completed handshake | Certificate collection / detection |
| --- | --- | --- |
| TLS 1.3 | Yes, through Go `crypto/tls` | Certificate collection requires reaching the encrypted certificate messages. |
| TLS 1.2, 1.1, 1.0 | Yes, with suites supported by Go | A bounded raw probe retries when Go cannot collect a certificate. |
| SSLv3 | No | Dedicated ClientHello; unencrypted ServerHello and Certificate messages only. |
| SSLv2 | No | Dedicated SSLv2 ClientHello and ServerHello; certificate and 24-bit cipher specs. |
| RSA key exchange, CBC, RC4-SHA, 3DES | Yes, where supported by Go and the server | Explicit suite offers; raw collection remains available on failure. |
| Export suites, RC4-MD5, DHE, DSA authentication | No in the raw collector | Certificate and protocol framing only; no legacy key exchange or application data. |
| Certificates signed with SHA-1 or MD5; RSA 1024-bit keys | Can complete with a mutually supported handshake | Certificate signature validity is not a condition for collecting DER. The backend classifies the certificate. |
| Weak finite-field DH | No in the raw collector | Reports the server modulus bit length when a well-formed ServerKeyExchange is received. This does not verify primality, parameter strength or the handshake signature. |

No `GODEBUG` override is required. The discovery connection explicitly offers
the legacy TLS versions and suites still implemented by Go. Deprecated flags
such as `tlsrsakex` and `tls3des` are not used. A server requiring a SHA-1
handshake signature may yield a certificate without a completed handshake;
Sentinel does not enable SHA-1 globally to change that outcome.

## Deep enumeration

A deep scan records the server's selections from the fixed `tls-cert-v1`
TLS 1.0–1.2 catalogue. It also probes SSLv3 and SSLv2 even when modern TLS works.
Those two probes address the default service at the same IP and port, **without
SNI**. They do not characterize a named virtual host's certificate.

An accepted suite is positive evidence from ServerHello, not proof that a full
handshake could finish. Partial results remain visible without a completeness
marker. Timeouts, resets and unsupported responses do not prove that a protocol
or suite is absent. The catalogue does not enumerate TLS 1.3 suites, all possible
signature/group offers, PSK/SRP credentials or client-certificate configurations.

## Bounds and limitations

The fallback tries at most six connections within ten seconds. It retries with
and without extensions and pins retries to the first connection's actual peer.
All connections share the scan's rate limit. Cancellation closes active probes.
The raw TLS reader accepts at most 1 MiB, 256 records, 16 handshake messages and
10 certificates of at most 64 KiB each. SSLv2 collection fits in one plaintext
record (at most 32,767 bytes). A response outside these bounds can produce only
partial evidence, or no observation.

The raw collector reads bounded protocol framing and copies opaque DER. It does
not parse X.509. The standard Go handshake necessarily parses peer certificates;
authoritative certificate interpretation stays in the backend sandbox.

An X.509 parse failure on a TLS 1.3-only server prevents certificate collection:
Go rejects the certificate before exposing its DER, and the raw fallback cannot
read TLS 1.3's encrypted Certificate message. For TLS 1.2 and earlier, the raw
fallback can retain unparseable DER within the framing and size limits. Collection
does not guarantee admission to the inventory: the backend sandbox may reject it.

Filesystem extraction also checks the outer certificate structure to exclude
private keys. Structurally invalid files are skipped. Certificate size and chain
limits may omit certificates; a collected chain is not necessarily complete.

These probes cover TLS over TCP, directly or after the preambles below. They do
not implement DTLS, QUIC, application authentication or a complete SSLv2/SSLv3
session. Discovery
connects directly to targets; the HTTP proxy setting applies to backend traffic.
The backend HTTPS connection retains normal certificate verification and is
separate from the permissive discovery connections.

## Application protocol preambles

Discovery omits ALPN so that HTTP protocol offers do not cause non-HTTP services
(such as MQTT) to reject the handshake. A service that requires a particular
ALPN offer may still refuse collection. The backend HTTPS transport is unchanged.

On these standard ports, every connection performs the indicated exchange before
TLS, including legacy fallback and deep enumeration:

| Port | Exchange before TLS |
| --- | --- |
| 21 | FTP greeting, `AUTH TLS` |
| 25, 587 | SMTP greeting, `EHLO sentinel.invalid`, advertised `STARTTLS` |
| 110 | POP3 greeting, `STLS` |
| 143 | IMAP greeting, `a001 STARTTLS` |
| 389 | LDAP StartTLS ExtendedRequest, OID `1.3.6.1.4.1.1466.20037` |
| 3389 | X.224 negotiation offering TLS and CredSSP; stop before authentication |
| 5432 | PostgreSQL SSLRequest; no startup message or database login |

Other ports use direct TLS, including SMTPS, IMAPS, POP3S, LDAPS, MQTT TLS,
Syslog TLS and Modbus Security. A custom direct-TLS port is supported; a STARTTLS
service moved to a nonstandard port is not automatically recognized. MySQL
negotiation and OPC UA GetEndpoints are not implemented. A port number selects
an exchange, not a guarantee that the service supports it.

A refusal ends discovery without trying other application protocols or sending
credentials. Preambles share the existing connection admission limits. Each has
a deadline bounded by the attempt timeout and cancellation; TLS then has its
own handshake budget. Text replies are bounded to 4 KiB per line, 16 KiB and
64 lines per connection. LDAP replies are limited to 4 KiB and RDP requires the
19-byte negotiation response. Server banners and diagnostics are not logged.
The collector retains certificate DER under the existing size/chain limits;
authoritative X.509 parsing remains on the backend.

Network scan defaults include 802, 6514 and 8883. Other STARTTLS ports must be
selected in the organization's existing port configuration; local listener
collection includes supported preamble ports. Custom port lists are preserved.

Protocol references: [SMTP (RFC 3207)](https://www.rfc-editor.org/rfc/rfc3207),
[IMAP/POP3 (RFC 2595)](https://www.rfc-editor.org/rfc/rfc2595),
[FTP (RFC 4217)](https://www.rfc-editor.org/rfc/rfc4217),
[LDAP (RFC 4511)](https://www.rfc-editor.org/rfc/rfc4511),
[RDP negotiation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3),
[PostgreSQL SSLRequest](https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-SSL).

## Tests

Loopback integration tests exercise each preamble with TLS 1.2/1.3, non-HTTP
ALPN services, raw certificate fallback and repeated cipher probes. The isolated
fixture below also runs these tests; they model protocol exchanges, not complete
mail, directory or desktop applications.

Unit tests cover fragmented, truncated and oversized messages, incorrect server
selections, cancellation and connection budgets. Native Go fuzzing exercises the
TLS and SSLv2 readers. `scripts/test-legacy-tls.sh` builds a test-only OpenSSL
1.0.2u fixture, verifies its source checksum and runs it with no external network,
no published port, no capabilities and a read-only root filesystem. Disposable
keys are generated at runtime. OpenSSL is not linked into or shipped with Sentinel.

The same isolated container runs Go TLS 1.2/1.3 servers with unusual certificates:
eight-year and year-9999 validity, CN-only and IP SAN names, missing issuers,
self-signed certificates, negative or non-minimal serials and invalid UTF-8.
Tests check retained DER bytes, bounded chain handling and successful probes after
rejections. Filesystem tests reuse these fixtures without X.509 interpretation in
the extraction path. TLS 1.3 parse rejection is an expected collection limitation.

## Scan modes and network identification

The organization's Scan Configuration selects Standard (the default) or Gentle
for its sentinels. Technical limits are fixed in the agent, not individual UI
settings. Standard keeps onboarding discovery and normal TLS analysis enabled.
Both modes allow only one open discovery connection per destination IP, across
ports and SNI names. Targets are interleaved across hosts.

Gentle uses at most five workers and five connection attempts per second, waits
one second after closing a connection before reconnecting to that IP, and gives
TLS handshakes up to ten seconds. It skips SAN-name reprobes and deep cipher
analysis; bounded legacy certificate fallback remains enabled. Missing analysis
is not evidence of a secure TLS configuration. Filesystem collection and Internet
scanning remain unchanged.

Update sentinels before enabling Gentle. Agents advertise support on task polls;
when Gentle is selected, the backend withholds tasks from unsupported agents.
Changes apply after the next poll, including subsequent CIDR batches; an active
batch is not interrupted. Local
`allow_network_scan: false` still forbids network scans regardless of cloud
configuration. Limits apply per sentinel, not across a fleet; avoid overlapping
scan scopes for fragile equipment.

For network monitoring, allow the sentinel host's source IP to the configured
TCP destinations and ports. Discovery connects directly, not through the backend
HTTP proxy. DNS uses the host's resolver. The initial probe sends a Go TLS
ClientHello with SNI for named targets and no ALPN, after any port-specific
preamble listed above, then closes the
connection without an HTTP request. Legacy fallback and deep scans send the
ClientHellos described above and may close before finishing the handshake.
TLS fingerprints can change with the Go version; do not treat one fingerprint
as a permanent identity or add a blanket IDS exception. Validate the selected
scope and rate on representative equipment before scanning an industrial network.

## Large network scopes

CIDR discovery traverses the union of usable IPv4 addresses and configured ports,
without the former 100,000-target sample. The scope is limited to 64 IPv4 ranges
from /16 to /32 and 32 ports. Duplicate ranges, overlapping addresses and repeated
ports do not add probes. Network and broadcast addresses are omitted for /16–/30;
both /31 addresses and explicit /32 hosts are included.

Targets are generated as needed, one port across the IPs before the next port.
A sweep runs in batches of up to 50 targets in Standard or five in Gentle, using
the existing connection limits. Between batches, due polls retrieve configuration
and dispatch other tasks, including targeted onboarding scans. One slow batch or
a targeted task can still delay a poll; the polling interval is not a scan deadline.
A repeated periodic task for the current scope does not restart the sweep.

Progress is a small file beside the configured key file, with the suffix
`.scan-progress.json`. It contains only a scope/agent fingerprint and a position,
not certificates or a report queue. The position advances after a batch has
finished and its reports have been accepted. Failed batches are probed again
after a polling interval; this is not durable storage of failed reports.
Only the end of the traversal produces a sweep completion report.

After restart, a new backend sweep task is required before progress is reused.
Changing the scope invalidates the running traversal and requires a new task.
Unreadable, invalid or incompatible progress starts a fresh traversal; a write
failure keeps scanning but a restart can repeat earlier work. An interrupted
batch can also be repeated. The local scan prohibition remains authoritative.
The cloud network switch governs new tasks; the current API has no command to
cancel an already authorized task.

Regression tests cover overlapping ranges and address boundaries, exhaustive
traversal beyond 100,000 targets, cancellation, checkpoint recovery and report
failures. Loopback tests exercise TLS collection and signed reports; a simulated
silent sweep checks that polling and targeted tasks run between batches. These
run with the regular Go tests, without external services or network fixtures.

## Backend polling and outage recovery

Sentinel uses short HTTP polls, not long polling. The first task poll is immediate.
Subsequent polls wait around the configured interval (30 seconds by default,
with a ±10% variation), measured after the previous response and dispatched tasks.
Consecutive failures increase this wait with jitter, up to five minutes at the
default cadence. A successful poll restores the normal interval. A configured
interval longer than five minutes is preserved during failures.

For HTTP 429 and 503, task polls, report retries and enrollment retries honor
valid `Retry-After` values up to one hour, as seconds or an HTTP date. A small
positive random margin, at most one second, spreads retries without sending them
before that minimum. Missing, invalid or excessive values use the local backoff.
The signed client also keeps this minimum between separate calls, including
after a report exhausts its attempts. Cancellation interrupts these waits.
Each HTTP request retains its 30-second
timeout; signed retries use fresh nonces.

Report delivery has four attempts per call. Targeted network scans retain a failed
batch in memory and retry temporary failures with increasing delays, up to five
minutes at the default cadence. Scanner buffers stay bounded. Other tasks and
configuration polls wait until delivery resumes; key rotation runs separately.
The completion report follows accepted data batches and is retried the same way.
Permanent refusals or invalid response signatures stop that scan's delivery.
Stopping or restarting the service discards pending results; there is no disk queue.

Enrollment has five attempts for network failures, 429 and 5xx, with a ten-second
initial backoff base; other HTTP errors and invalid successful response payloads
stop that enrollment attempt. Signed response verification remains required for
successful task/report exchanges.

Tests use Go's simulated clock for long retry delays and loopback HTTP for
polling recovery, slow responses, cancellation and enrollment status handling.
They run in the existing Go test job without a new service or dependency.
