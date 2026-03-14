# Usage guide

## Architecture

The extension has three core objects:

- **Context** (`BoringSSL\Context`) -- Holds shared TLS configuration. Create one, configure it, then spawn connections from it. One context can produce many connections.
- **Connection** (`BoringSSL\Connection`) -- A single TLS session over a socket. Created via `$ctx->newConnection()`. Handles handshake, I/O, and shutdown.
- **Session** (`BoringSSL\Session`) -- A serializable TLS session ticket for resumption. Obtained from a completed connection, applied to a new one before the handshake.

## OOP vs procedural

The extension provides two equivalent APIs. The OOP API supports method chaining. The procedural API takes the context or connection as the first argument and returns `true` on success.

**OOP:**
```php
$ctx = (new BoringSSL\Context())->new()
    ->setGroupsList('X25519:P-256')
    ->setGreaseEnabled(true);

$conn = $ctx->newConnection()->setStream($tcp);
$conn->connect();
```

**Procedural:**
```php
$ctx = boringssl_context_new();
boringssl_context_set_groups_list($ctx, 'X25519:P-256');
boringssl_context_set_grease($ctx, true);

$conn = boringssl_new_connection($ctx);
boringssl_set_stream($conn, $tcp);
boringssl_connect($conn);
```

Both APIs operate on the same underlying objects. You can mix them freely -- a context created with `boringssl_context_new()` can be passed to OOP methods and vice versa.

The rest of this guide shows the OOP API. Every example has a procedural equivalent; see the [function reference](#procedural-function-reference) for the mapping.

## Context setup

### Client context

```php
// OOP
$ctx = (new BoringSSL\Context())->new();

// Procedural
$ctx = boringssl_context_new();
```

### Server context

```php
// OOP
$ctx = (new BoringSSL\Context())->newServer()
    ->useCertificateChainFile('/path/to/cert.pem')
    ->usePrivateKeyFile('/path/to/key.pem');

// Procedural
$ctx = boringssl_context_new_server();
boringssl_context_use_certificate_file($ctx, '/path/to/cert.pem');
boringssl_context_use_private_key_file($ctx, '/path/to/key.pem');
```

A context can only be initialized once. Calling `new()` or `newServer()` a second time throws `BoringSSL\Exception`.

## Protocol versions

```php
$ctx->setMinProtoVersion(BoringSSL\TLS1_2_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION);
```

Available: `TLS1_VERSION`, `TLS1_1_VERSION`, `TLS1_2_VERSION`, `TLS1_3_VERSION`.

## Cipher control

### TLS 1.2 ciphers

```php
$ctx->setCipherList('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256');
```

Uses OpenSSL cipher string syntax. Only affects TLS 1.2 and below.

### TLS 1.3 ciphers

BoringSSL does not allow configuring TLS 1.3 cipher suites. They have a built-in preference order and are always all enabled. Calling `setCipherSuites()` emits an `E_NOTICE` and is a no-op. This is a fundamental difference from OpenSSL.

## ALPN (Application-Layer Protocol Negotiation)

ALPN advertises which application protocols the client supports. The server selects one during the handshake.

```php
$ctx->setAlpnProtos(['h2', 'http/1.1']);
```

Each protocol name must be 1-255 bytes. The array must not be empty.

After the handshake, query which protocol was selected:

```php
$proto = $conn->getNegotiatedAlpn();  // e.g., "h2", or "" if none
```

## Supported groups (curves)

```php
$ctx->setGroupsList('X25519:P-256:P-384');
```

Common values: `X25519`, `P-256`, `P-384`, `P-521`, `X25519MLKEM768` (post-quantum hybrid).

### Post-quantum key exchange

```php
$ctx->setGroupsList('X25519MLKEM768:X25519:P-256');
```

`X25519MLKEM768` is a hybrid post-quantum key exchange combining X25519 with ML-KEM-768. List classical groups as fallbacks for servers that don't support it.

## Signature algorithms

```php
$ctx->setVerifyAlgorithmPrefs([
    BoringSSL\SIGALG_ECDSA_SECP256R1_SHA256,
    BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
    BoringSSL\SIGALG_RSA_PKCS1_SHA256,
    BoringSSL\SIGALG_ECDSA_SECP384R1_SHA384,
    BoringSSL\SIGALG_RSA_PSS_RSAE_SHA384,
    BoringSSL\SIGALG_RSA_PKCS1_SHA384,
    BoringSSL\SIGALG_RSA_PSS_RSAE_SHA512,
    BoringSSL\SIGALG_RSA_PKCS1_SHA512,
]);
```

`setVerifyAlgorithmPrefs()` controls which signature algorithms are accepted when verifying the server's certificate chain. `setSigningAlgorithmPrefs()` controls which are offered for client-side signing (mutual TLS).

Values must be in the range 0-65535 (IANA TLS SignatureScheme registry). The array must not be empty.

## GREASE

[GREASE](https://www.rfc-editor.org/rfc/rfc8701) injects unknown reserved values into the ClientHello to test server tolerance. Widely used by browsers.

```php
$ctx->setGreaseEnabled(true);
```

Each connection will use randomized GREASE values.

## Extension permutation

Randomizes the order of TLS extensions in the ClientHello on each connection.

```php
$ctx->setPermuteExtensions(true);
```

## Certificate compression

Registers compression algorithms for RFC 8879 TLS Certificate Compression. The server chooses which to use based on its preference.

```php
$ctx->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_BROTLI);
$ctx->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_ZLIB);
$ctx->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_ZSTD);
```

Requires the corresponding libraries to be available at build time (libbrotli, zlib, libzstd). Calling with an unsupported algorithm throws `ValueError`.

## ALPS (Application-Layer Protocol Settings)

Application-Layer Protocol Settings allow sending opaque settings frames to the peer during the handshake.

```php
$ctx->addApplicationSettings('h2', '')
    ->setAlpsUseNewCodepoint(true);
```

Multiple protocol/settings pairs can be added. The settings value is an opaque binary string. `setAlpsUseNewCodepoint(true)` uses the newer ALPS extension codepoint.

After the handshake:

```php
$peer_settings = $conn->getPeerApplicationSettings('h2');
```

## Encrypted Client Hello (ECH)

ECH encrypts the ClientHello to prevent network observers from seeing the target hostname.

```php
// Obtain ECHConfigList (typically from DNS HTTPS records)
$ech_config = get_ech_config_from_dns('example.com');
$ctx->setEchConfigList($ech_config);
```

After the handshake:

```php
$status = $conn->getEchStatus();
// BoringSSL\ECH_STATUS_SUCCESS        -- ECH was accepted
// BoringSSL\ECH_STATUS_REJECTED       -- ECH was rejected; retry configs available
// BoringSSL\ECH_STATUS_NOT_NEGOTIATED -- ECH was not attempted

if ($status === BoringSSL\ECH_STATUS_REJECTED) {
    $retry = $conn->getEchRetryConfigs();
    // Retry with updated config
}
```

## Certificate verification

```php
// Peer verification (client verifying server)
$ctx->setVerify(BoringSSL\VERIFY_PEER);
$ctx->loadVerifyLocations('/etc/ssl/certs/ca-certificates.crt');

// Or with a CA directory
$ctx->loadVerifyLocations('/etc/ssl/certs/ca-certificates.crt', '/etc/ssl/certs');

// No verification (testing only)
$ctx->setVerify(BoringSSL\VERIFY_NONE);
```

For server contexts requiring client certificates:

```php
$ctx->setVerify(BoringSSL\VERIFY_PEER | BoringSSL\VERIFY_FAIL_IF_NO_CERT);
```

**Note:** Custom verify callbacks are not yet supported. Passing a callback to `setVerify()` will throw an exception.

### System CA store

```php
$ctx->setDefaultVerifyPaths();
```

Loads the platform's default CA certificate bundle. On most Linux systems this finds `/etc/ssl/certs`.

### Verify depth

```php
$ctx->setVerifyDepth(10);
```

Limits how many intermediate certificates are allowed in the chain.

### Hostname verification (SNI)

```php
$conn = $ctx->newConnection()->setStream($tcp);
$conn->setHostname('example.com');
$conn->connect();
```

`setHostname()` sets the SNI extension and must be called before `connect()`. After the handshake, check the verification result:

```php
$result = $conn->getVerifyResult();
if ($result !== BoringSSL\X509_V_OK) {
    echo "Verification failed: $result\n";
}
```

### Peer certificate inspection

```php
// End-entity certificate as PEM
$pem = $conn->getPeerCertificate();  // string or null

// Full chain as array of PEM strings
$chain = $conn->getPeerCertificateChain();  // string[]
```

## Server certificates and keys

```php
// Single certificate
$ctx->useCertificateFile('/path/to/cert.pem');

// Full chain
$ctx->useCertificateChainFile('/path/to/fullchain.pem');

// Private key (verified against loaded certificate)
$ctx->usePrivateKeyFile('/path/to/key.pem');
```

All paths are validated against PHP's `open_basedir` setting.

### In-memory certificates and keys

Load certificates and keys from PEM strings instead of files:

```php
$ctx->useCertificateChainPem($certPem)
    ->usePrivateKeyPem($keyPem);
```

### Client CA list (mTLS)

For servers requiring client certificates, specify which CAs are acceptable:

```php
$ctx->loadClientCAFile('/path/to/client-cas.pem');
```

### Session ticket keys

For multi-server deployments, set shared ticket encryption keys (exactly 48 bytes):

```php
$keys = random_bytes(48);
$ctx->setSessionTicketKeys($keys);
```

## Early data (0-RTT)

TLS 1.3 early data allows sending application data during the handshake on resumed connections.

```php
// Enable on the context
$ctx->setEarlyDataEnabled(true);

// First connection (establishes session)
$conn1 = $ctx->newConnection()->setStream($tcp1);
$conn1->connect();
$session = $conn1->getSession();
$conn1->shutdown();

// Second connection (uses early data)
$conn2 = $ctx->newConnection()->setStream($tcp2);
$conn2->setSession($session);
$conn2->writeEarlyData("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
$conn2->connect();

$status = $conn2->getEarlyDataStatus();
// BoringSSL\EARLY_DATA_ACCEPTED  -- server accepted early data
// BoringSSL\EARLY_DATA_REJECTED  -- server rejected; data must be resent
// BoringSSL\EARLY_DATA_NOT_SENT  -- no early data was sent
```

**Warning:** Early data can be replayed by a network attacker. Only send idempotent requests as early data.

## Session resumption

```php
// After a completed handshake
$session = $conn->getSession();
if ($session) {
    $bytes = $session->toBytes();
    // Store $bytes (e.g., in cache)

    $id      = $session->getId();
    $timeout = $session->getTimeout();
    $ticket  = $session->hasTicket();
}

// Later, restore and apply before connect()
$session = BoringSSL\Session::fromBytes($bytes, $ctx);
$conn = $ctx->newConnection()->setStream($tcp);
$conn->setSession($session);
$conn->connect();
```

`setSession()` must be called before `connect()`.

## Connections

### From a PHP stream

```php
$tcp = stream_socket_client('tcp://example.com:443', $errno, $errstr, 10);
$conn = $ctx->newConnection()->setStream($tcp);
```

Works with `stream_socket_client()`, `fsockopen()`, and streams created from `socket_export_stream()`.

### From a raw file descriptor

```php
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($sock, gethostbyname('example.com'), 443);
$stream = socket_export_stream($sock);
$conn = $ctx->newConnection()->setStream($stream);
```

You can also use `setFd()` directly with an integer file descriptor, but `setStream()` is preferred because it manages the fd lifetime correctly.

### Handshake

```php
// Client
$result = $conn->connect();    // true on success, false on WANT_READ/WANT_WRITE

// Server
$result = $conn->accept();     // true on success, false on WANT_READ/WANT_WRITE
```

Both throw `BoringSSL\Exception` on hard failures.

### Reading and writing

```php
$conn->write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

$data = $conn->read(4096);     // Returns string, empty string on WANT_READ, false on EOF

$pending = $conn->pending();   // Bytes buffered in SSL, ready to read without blocking
```

`write()` returns the number of bytes written. `read()` accepts a maximum length between 1 and 2,147,483,647.

### Shutdown

```php
$result = $conn->shutdown();   // true = fully closed, false = close_notify sent (call again)
```

### Inspecting the connection

```php
$conn->getNegotiatedCipher();      // e.g., "TLS_AES_128_GCM_SHA256"
$conn->getNegotiatedAlpn();        // e.g., "h2", or "" if not negotiated
$conn->getNegotiatedGroup();       // e.g., "X25519"
$conn->getProtocolVersion();       // e.g., 0x0304 (TLS 1.3)
$conn->getEchStatus();             // ECH_STATUS_* constant
$conn->getEchRetryConfigs();       // Binary ECHConfigList or empty string
$conn->getPeerApplicationSettings('h2');  // ALPS settings or empty string
$conn->getEarlyDataStatus();       // EARLY_DATA_* constant
$conn->getError();                 // Last SSL error code
$conn->getErrorString();           // Last SSL error as human-readable string
```

## OCSP stapling

Request OCSP stapled responses from the server:

```php
$ctx->enableOcspStapling(true);
```

After the handshake, retrieve the stapled response (DER-encoded):

```php
$ocsp = $conn->getOcspResponse();  // binary string, or "" if not stapled
```

## Signed Certificate Timestamps (SCT)

Request SCT data for Certificate Transparency verification:

```php
$ctx->enableSignedCertTimestamps(true);
```

After the handshake:

```php
$scts = $conn->getSignedCertTimestamps();  // binary string, or ""
```

## SSL options

Control protocol-level behavior via option flags:

```php
$ctx->setOptions(BoringSSL\SSL_OP_NO_TICKET | BoringSSL\SSL_OP_CIPHER_SERVER_PREFERENCE);
$ctx->clearOptions(BoringSSL\SSL_OP_NO_TICKET);
$current = $ctx->getOptions();
```

Available: `SSL_OP_NO_TICKET`, `SSL_OP_CIPHER_SERVER_PREFERENCE`, `SSL_OP_ALL`.

## Non-destructive read (peek)

Read data without consuming it from the SSL buffer:

```php
$data = $conn->peek(4096);  // same return semantics as read()
```

## TLS 1.3 key update

Rotate encryption keys on a live connection:

```php
$conn->keyUpdate();
```

## Renegotiation control

Control TLS renegotiation behavior (TLS 1.2 and below):

```php
$conn->setRenegotiateMode(BoringSSL\RENEGOTIATE_ONCE);
```

Available: `RENEGOTIATE_NEVER`, `RENEGOTIATE_ONCE`, `RENEGOTIATE_FREELY`, `RENEGOTIATE_IGNORE`, `RENEGOTIATE_EXPLICIT`.

## Export keying material

Derive keying material from the TLS session (RFC 5705):

```php
$material = $conn->exportKeyingMaterial('EXPORTER-my-protocol', 32, $context);
```

The `$context` parameter is optional. Returns a binary string of the requested length.

## Session reuse check

After a handshake with a session set, confirm whether the server accepted it:

```php
if ($conn->isSessionReused()) {
    echo "Session was resumed\n";
}
```

## Keylog file (Wireshark debugging)

Write TLS secrets in SSLKEYLOGFILE format for packet decryption:

```php
$ctx->setKeylogFile('/tmp/sslkeys.log');
```

Then in Wireshark: Edit > Preferences > TLS > (Pre)-Master-Secret log filename.

## Session cache modes

```php
$ctx->setSessionCacheMode(0);  // Disable server-side session cache
```

This maps directly to BoringSSL's `SSL_CTX_set_session_cache_mode`. Refer to the BoringSSL documentation for valid mode values.

## Error handling

All errors throw `BoringSSL\Exception` (extends `RuntimeException`). The exception message includes the BoringSSL error string when available.

```php
try {
    $conn->connect();
} catch (BoringSSL\Exception $e) {
    echo $e->getMessage();
    // e.g., "SSL handshake failed: CERTIFICATE_VERIFY_FAILED"
}
```

Input validation errors (wrong types, out-of-range values) throw `ValueError` or `TypeError`, consistent with PHP conventions.

## Full example: TLS 1.3 with fingerprint features

```php
$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_2_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setCipherList(
        'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:' .
        'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:' .
        'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
    )
    ->setGroupsList('X25519MLKEM768:X25519:P-256:P-384')
    ->setVerifyAlgorithmPrefs([
        BoringSSL\SIGALG_ECDSA_SECP256R1_SHA256,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
        BoringSSL\SIGALG_RSA_PKCS1_SHA256,
        BoringSSL\SIGALG_ECDSA_SECP384R1_SHA384,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA384,
        BoringSSL\SIGALG_RSA_PKCS1_SHA384,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA512,
        BoringSSL\SIGALG_RSA_PKCS1_SHA512,
    ])
    ->setGreaseEnabled(true)
    ->setPermuteExtensions(true)
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_BROTLI)
    ->addApplicationSettings('h2', '')
    ->setAlpsUseNewCodepoint(true);

$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
stream_set_timeout($tcp, 5);

$conn = $ctx->newConnection()->setStream($tcp);
$conn->connect();

echo "Cipher:   " . $conn->getNegotiatedCipher()  . "\n";
echo "Group:    " . $conn->getNegotiatedGroup()    . "\n";
echo "Protocol: 0x" . dechex($conn->getProtocolVersion()) . "\n";

$conn->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");

$body = '';
while (($chunk = $conn->read(4096)) !== false && $chunk !== '') {
    $body .= $chunk;
}

echo "Received " . strlen($body) . " bytes\n";
$conn->shutdown();
```

## Full example: loopback server and client

```php
// Generate a self-signed cert for testing
$key = openssl_pkey_new(['private_key_bits' => 2048]);
$csr = openssl_csr_new(['CN' => 'localhost'], $key);
$cert = openssl_csr_sign($csr, null, $key, 365);

openssl_x509_export_to_file($cert, '/tmp/test-cert.pem');
openssl_pkey_export_to_file($key, '/tmp/test-key.pem');

// Server context
$server_ctx = (new BoringSSL\Context())->newServer()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->useCertificateFile('/tmp/test-cert.pem')
    ->usePrivateKeyFile('/tmp/test-key.pem');

// Client context
$client_ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->setVerify(BoringSSL\VERIFY_NONE);

// Unix socket pair
socket_create_pair(AF_UNIX, SOCK_STREAM, 0, $pair);

$pid = pcntl_fork();
if ($pid === 0) {
    // Child: server
    socket_close($pair[0]);
    $stream = socket_export_stream($pair[1]);
    $conn = $server_ctx->newConnection()->setStream($stream);
    $conn->accept();
    $data = $conn->read(1024);
    $conn->write(strtoupper($data));
    $conn->shutdown();
    exit(0);
}

// Parent: client
socket_close($pair[1]);
$stream = socket_export_stream($pair[0]);
$conn = $client_ctx->newConnection()->setStream($stream);
$conn->connect();
$conn->write('hello');
echo $conn->read(1024) . "\n";  // "HELLO"
$conn->shutdown();

pcntl_wait($status);
```

## Full example: procedural API

```php
$ctx = boringssl_context_new();
boringssl_context_set_min_proto_version($ctx, BoringSSL\TLS1_2_VERSION);
boringssl_context_set_max_proto_version($ctx, BoringSSL\TLS1_3_VERSION);
boringssl_context_set_cipher_list($ctx,
    'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:' .
    'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:' .
    'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
);
boringssl_context_set_groups_list($ctx, 'X25519MLKEM768:X25519:P-256:P-384');
boringssl_context_set_verify_algorithm_prefs($ctx, [
    BoringSSL\SIGALG_ECDSA_SECP256R1_SHA256,
    BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
    BoringSSL\SIGALG_RSA_PKCS1_SHA256,
]);
boringssl_context_set_grease($ctx, true);
boringssl_context_set_permute_extensions($ctx, true);
boringssl_context_add_cert_compression_alg($ctx, BoringSSL\CERT_COMPRESS_BROTLI);
boringssl_context_add_application_settings($ctx, 'h2', '');
boringssl_context_set_alps_use_new_codepoint($ctx, true);

$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);

$conn = boringssl_new_connection($ctx);
boringssl_set_stream($conn, $tcp);
boringssl_connect($conn);

echo "Cipher:   " . boringssl_get_cipher($conn)  . "\n";
echo "Group:    " . boringssl_get_group($conn)    . "\n";
echo "Protocol: 0x" . dechex(boringssl_get_version($conn)) . "\n";

boringssl_write($conn, "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");

$body = '';
while (($chunk = boringssl_read($conn, 4096)) !== false && $chunk !== '') {
    $body .= $chunk;
}

echo "Received " . strlen($body) . " bytes\n";
boringssl_shutdown($conn);
```

## Procedural function reference

### Context functions

| Function | Returns | Description |
|---|---|---|
| `boringssl_context_new()` | `Context` | Create a client context |
| `boringssl_context_new_server()` | `Context` | Create a server context |
| `boringssl_context_set_cipher_list($ctx, string $ciphers)` | `true` | Set TLS 1.2 cipher list |
| `boringssl_context_set_alpn_protos($ctx, array $protocols)` | `true` | Set ALPN protocol list |
| `boringssl_context_set_groups_list($ctx, string $groups)` | `true` | Set supported groups |
| `boringssl_context_set_verify_algorithm_prefs($ctx, array $ids)` | `true` | Set verify signature algorithms |
| `boringssl_context_set_signing_algorithm_prefs($ctx, array $ids)` | `true` | Set signing signature algorithms |
| `boringssl_context_set_grease($ctx, bool $enabled)` | `true` | Enable/disable GREASE |
| `boringssl_context_set_permute_extensions($ctx, bool $enabled)` | `true` | Enable/disable extension permutation |
| `boringssl_context_add_application_settings($ctx, string $proto, string $settings)` | `true` | Add ALPS entry |
| `boringssl_context_set_alps_use_new_codepoint($ctx, bool $enabled)` | `true` | Use new ALPS codepoint |
| `boringssl_context_add_cert_compression_alg($ctx, int $algId)` | `true` | Register cert compression algorithm |
| `boringssl_context_set_ech_config_list($ctx, string $config)` | `true` | Set ECH config |
| `boringssl_context_set_min_proto_version($ctx, int $version)` | `true` | Set minimum protocol version |
| `boringssl_context_set_max_proto_version($ctx, int $version)` | `true` | Set maximum protocol version |
| `boringssl_context_set_early_data($ctx, bool $enabled)` | `true` | Enable/disable early data |
| `boringssl_context_use_certificate_file($ctx, string $path)` | `true` | Load certificate from PEM file |
| `boringssl_context_use_private_key_file($ctx, string $path)` | `true` | Load private key from PEM file |
| `boringssl_context_load_verify_locations($ctx, string $caFile [, string $caPath])` | `true` | Load CA trust store |
| `boringssl_context_set_verify($ctx, int $mode)` | `true` | Set verification mode |
| `boringssl_context_set_default_verify_paths($ctx)` | `true` | Load system CA store |
| `boringssl_context_set_verify_depth($ctx, int $depth)` | `true` | Set chain depth limit |
| `boringssl_context_set_options($ctx, int $options)` | `true` | Set SSL option flags |
| `boringssl_context_clear_options($ctx, int $options)` | `true` | Clear SSL option flags |
| `boringssl_context_get_options($ctx)` | `int` | Get current option flags |
| `boringssl_context_enable_ocsp_stapling($ctx, bool $enabled)` | `true` | Enable OCSP stapling |
| `boringssl_context_enable_signed_cert_timestamps($ctx, bool $enabled)` | `true` | Enable SCT |
| `boringssl_context_set_keylog_file($ctx, string $path)` | `true` | Set SSLKEYLOGFILE path |
| `boringssl_context_load_client_ca_file($ctx, string $path)` | `true` | Load client CAs for mTLS |
| `boringssl_context_set_session_ticket_keys($ctx, string $keys)` | `true` | Set 48-byte ticket keys |
| `boringssl_context_use_certificate_chain_pem($ctx, string $pem)` | `true` | Load cert chain from PEM string |
| `boringssl_context_use_private_key_pem($ctx, string $pem)` | `true` | Load private key from PEM string |

### Connection functions

| Function | Returns | Description |
|---|---|---|
| `boringssl_new_connection($ctx)` | `Connection` | Create connection from context |
| `boringssl_set_fd($conn, int $fd)` | `true` | Attach raw file descriptor |
| `boringssl_set_stream($conn, resource $stream)` | `true` | Attach PHP stream |
| `boringssl_connect($conn)` | `bool` | Perform client handshake |
| `boringssl_accept($conn)` | `bool` | Perform server handshake |
| `boringssl_read($conn, int $length)` | `string\|false` | Read decrypted data |
| `boringssl_write($conn, string $data)` | `int` | Write data, returns bytes written |
| `boringssl_pending($conn)` | `int` | Bytes buffered in SSL |
| `boringssl_shutdown($conn)` | `bool` | Send/complete TLS shutdown |
| `boringssl_get_cipher($conn)` | `string` | Negotiated cipher name |
| `boringssl_get_alpn_proto($conn)` | `string` | Negotiated ALPN protocol |
| `boringssl_get_group($conn)` | `string` | Negotiated key exchange group |
| `boringssl_get_version($conn)` | `int` | Negotiated protocol version |
| `boringssl_get_session($conn)` | `Session\|null` | Get session for resumption |
| `boringssl_set_session($conn, $session)` | `true` | Set session for resumption |
| `boringssl_set_hostname($conn, string $hostname)` | `true` | Set SNI hostname |
| `boringssl_get_verify_result($conn)` | `int` | X509 verification result |
| `boringssl_session_reused($conn)` | `bool` | Whether session was resumed |
| `boringssl_peek($conn, int $length)` | `string\|false` | Non-destructive read |
| `boringssl_key_update($conn)` | `true` | TLS 1.3 key rotation |
| `boringssl_get_ocsp_response($conn)` | `string` | OCSP stapled response (DER) |
| `boringssl_get_signed_cert_timestamps($conn)` | `string` | SCT list (binary) |
| `boringssl_get_peer_certificate($conn)` | `string\|null` | Peer cert as PEM |
| `boringssl_get_peer_certificate_chain($conn)` | `array` | Cert chain as PEM array |
| `boringssl_export_keying_material($conn, string $label, int $len [, string $ctx])` | `string` | Derived key material |
| `boringssl_set_renegotiate_mode($conn, int $mode)` | `true` | Set renegotiation mode |

### Session functions

| Function | Returns | Description |
|---|---|---|
| `boringssl_session_from_bytes(string $bytes, $ctx)` | `Session` | Deserialize a session |
| `boringssl_session_to_bytes($session)` | `string` | Serialize a session |
| `boringssl_session_get_id($session)` | `string` | Get session ID |
| `boringssl_session_get_timeout($session)` | `int` | Get session timeout in seconds |
| `boringssl_session_has_ticket($session)` | `bool` | Whether session has a ticket |
