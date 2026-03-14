# Migrating from ext-openssl

This guide covers the differences between PHP's built-in `ext-openssl` and `ext-boringssl`, and how to translate common patterns.

## Why migrate

PHP's `ext-openssl` wraps OpenSSL and exposes TLS through high-level functions like `stream_socket_enable_crypto()` and context options. This works well for standard HTTPS, but makes it impossible to control low-level TLS behavior: cipher suite ordering, extension permutation, GREASE, certificate compression, ALPS, ECH, post-quantum key exchange, and other features only available in BoringSSL.

If you need fine-grained control over the TLS ClientHello, `ext-openssl` cannot help you.

## Key differences

### Two APIs to choose from

`ext-openssl` uses stream context options and procedural functions. `ext-boringssl` provides both an object-oriented API (with method chaining) and a procedural API. Pick whichever fits your codebase.

**ext-openssl:**
```php
$ctx = stream_context_create(['ssl' => [
    'verify_peer' => true,
    'cafile' => '/etc/ssl/certs/ca-certificates.crt',
]]);
$fp = stream_socket_client('ssl://example.com:443', $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx);
fwrite($fp, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
$data = fread($fp, 4096);
fclose($fp);
```

**ext-boringssl (OOP):**
```php
$ctx = (new BoringSSL\Context())->new()
    ->setVerify(BoringSSL\VERIFY_PEER)
    ->loadVerifyLocations('/etc/ssl/certs/ca-certificates.crt');

$tcp = stream_socket_client('tcp://example.com:443', $errno, $errstr, 10);
$conn = $ctx->newConnection()->setStream($tcp);
$conn->connect();
$conn->write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
$data = $conn->read(4096);
$conn->shutdown();
```

**ext-boringssl (procedural):**
```php
$ctx = boringssl_context_new();
boringssl_context_set_verify($ctx, BoringSSL\VERIFY_PEER);
boringssl_context_load_verify_locations($ctx, '/etc/ssl/certs/ca-certificates.crt');

$tcp = stream_socket_client('tcp://example.com:443', $errno, $errstr, 10);
$conn = boringssl_new_connection($ctx);
boringssl_set_stream($conn, $tcp);
boringssl_connect($conn);
boringssl_write($conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
$data = boringssl_read($conn, 4096);
boringssl_shutdown($conn);
```

In all cases, the TCP connection and TLS handshake are separate steps. You connect TCP first, then perform the TLS handshake over it.

### TLS 1.3 cipher suites

**ext-openssl:**
```php
// OpenSSL lets you configure TLS 1.3 ciphers
$ctx = stream_context_create(['ssl' => [
    'ciphers' => 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
]]);
```

**ext-boringssl:**
```php
// BoringSSL does not allow configuring TLS 1.3 cipher suites.
// They have a fixed preference order and are always all enabled.
// setCipherSuites() is a no-op that emits E_NOTICE.
// Only TLS 1.2 ciphers are configurable:
$ctx->setCipherList('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384');
```

This is a fundamental architectural difference in BoringSSL, not a limitation of this extension.

### Supported groups (curves)

**ext-openssl** (PHP 8.3+):
```php
// PHP 8.3 added openssl_get_curve_names(), but runtime selection
// via stream context is limited and version-dependent
```

**ext-boringssl:**
```php
$ctx->setGroupsList('X25519MLKEM768:X25519:P-256:P-384');
```

Groups are specified as a colon-separated string, including post-quantum hybrids.

### Signature algorithms

**ext-openssl:** No direct API.

**ext-boringssl:**
```php
$ctx->setVerifyAlgorithmPrefs([
    BoringSSL\SIGALG_ECDSA_SECP256R1_SHA256,
    BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
]);
```

### Verify modes

**ext-openssl:**
```php
$ctx = stream_context_create(['ssl' => [
    'verify_peer'       => true,
    'verify_peer_name'  => true,
    'allow_self_signed' => false,
]]);
```

**ext-boringssl:**
```php
$ctx->setVerify(BoringSSL\VERIFY_PEER)
    ->loadVerifyLocations('/etc/ssl/certs/ca-certificates.crt');
```

| ext-openssl option | ext-boringssl OOP | ext-boringssl procedural |
|---|---|---|
| `verify_peer => true` | `->setVerify(VERIFY_PEER)` | `boringssl_context_set_verify($ctx, VERIFY_PEER)` |
| `verify_peer => false` | `->setVerify(VERIFY_NONE)` | `boringssl_context_set_verify($ctx, VERIFY_NONE)` |
| `cafile => '/path'` | `->loadVerifyLocations('/path')` | `boringssl_context_load_verify_locations($ctx, '/path')` |
| `capath => '/dir'` | `->loadVerifyLocations($f, '/dir')` | `boringssl_context_load_verify_locations($ctx, $f, '/dir')` |
| `local_cert => '/path'` | `->useCertificateFile('/path')` | `boringssl_context_use_certificate_file($ctx, '/path')` |
| `local_pk => '/path'` | `->usePrivateKeyFile('/path')` | `boringssl_context_use_private_key_file($ctx, '/path')` |
| `verify_peer_name => true` | `$conn->setHostname($host)` + `$conn->getVerifyResult()` | `boringssl_set_hostname()` + `boringssl_get_verify_result()` |

**Note:** `ext-boringssl` does not currently expose hostname verification (`SSL_set1_host` / `SSL_set_tlsext_host_name`). If you require hostname checking, verify the peer certificate's subject/SAN manually after the handshake, or continue using `ext-openssl` for that connection.

### Protocol version pinning

**ext-openssl:**
```php
stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
```

**ext-boringssl:**
```php
$ctx->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION);
```

### Certificates and private keys

**ext-openssl:**
```php
$ctx = stream_context_create(['ssl' => [
    'local_cert' => '/path/to/cert.pem',
    'local_pk'   => '/path/to/key.pem',
]]);
```

**ext-boringssl:**
```php
$ctx->useCertificateChainFile('/path/to/cert.pem')
    ->usePrivateKeyFile('/path/to/key.pem');
```

`usePrivateKeyFile()` automatically verifies the key matches the loaded certificate and throws if it doesn't.

### Session resumption

**ext-openssl:** No direct API. PHP's OpenSSL stream wrapper handles sessions internally.

**ext-boringssl (OOP):**
```php
$session = $conn->getSession();
$bytes = $session->toBytes();

$session = BoringSSL\Session::fromBytes($bytes, $ctx);
$conn->setSession($session);
$conn->connect();
```

**ext-boringssl (procedural):**
```php
$session = boringssl_get_session($conn);
$bytes = boringssl_session_to_bytes($session);

$session = boringssl_session_from_bytes($bytes, $ctx);
boringssl_set_session($conn, $session);
boringssl_connect($conn);
```

You have full control over session storage, lifetime, and reuse.

### Error handling

**ext-openssl:**
```php
$fp = @stream_socket_client('ssl://example.com:443', $errno, $errstr);
if (!$fp) {
    echo "Error $errno: $errstr";
}
// Or check openssl_error_string() in a loop
```

**ext-boringssl:**
```php
try {
    $conn->connect();
} catch (BoringSSL\Exception $e) {
    echo $e->getMessage();
}
```

All failures throw `BoringSSL\Exception` with the BoringSSL error message included. No need to poll error queues.

## Features with no ext-openssl equivalent

These features are only available in ext-boringssl:

| Feature | OOP | Procedural |
|---|---|---|
| GREASE (RFC 8701) | `setGreaseEnabled(true)` | `boringssl_context_set_grease($ctx, true)` |
| Extension permutation | `setPermuteExtensions(true)` | `boringssl_context_set_permute_extensions($ctx, true)` |
| Certificate compression (RFC 8879) | `addCertCompressionAlg()` | `boringssl_context_add_cert_compression_alg()` |
| ALPS | `addApplicationSettings()` | `boringssl_context_add_application_settings()` |
| ALPS new codepoint | `setAlpsUseNewCodepoint(true)` | `boringssl_context_set_alps_use_new_codepoint()` |
| Encrypted Client Hello | `setEchConfigList()` | `boringssl_context_set_ech_config_list()` |
| Post-quantum key exchange | `setGroupsList('X25519MLKEM768:...')` | `boringssl_context_set_groups_list()` |
| Signature algorithm control | `setVerifyAlgorithmPrefs()` | `boringssl_context_set_verify_algorithm_prefs()` |
| TLS early data (0-RTT) | `setEarlyDataEnabled(true)` | `boringssl_context_set_early_data($ctx, true)` |
| Session control | `getSession()`, `setSession()` | `boringssl_get_session()`, `boringssl_set_session()` |

## Features in ext-openssl not available here

| ext-openssl feature | Status |
|---|---|
| `stream_socket_enable_crypto()` | Use `$conn->connect()` / `$conn->accept()` instead |
| `openssl_encrypt()` / `openssl_decrypt()` | Not in scope. This extension is TLS-only |
| `openssl_sign()` / `openssl_verify()` | Not in scope |
| `openssl_x509_parse()` | Not in scope |
| `openssl_csr_new()` | Not in scope |
| `openssl_pkey_*()` | Not in scope |
| PKCS7/CMS functions | Not in scope |
| Custom verify callbacks | Not yet implemented |
| ALPN (`alpn_protocols` option) | `setAlpnProtos(['h2', 'http/1.1'])` / `boringssl_context_set_alpn_protos()` |
| Capture peer certificate | `$conn->getPeerCertificate()` / `boringssl_get_peer_certificate()` |

`ext-boringssl` focuses on TLS transport. It does not replace the cryptographic utility functions in `ext-openssl` (encryption, signing, CSR generation, X.509 parsing). You can load both extensions simultaneously.

## Running both extensions

`ext-boringssl` and `ext-openssl` can coexist. They link against different libraries (BoringSSL vs OpenSSL) with separate symbol namespaces and have no PHP-level conflicts. Use `ext-openssl` for its utility functions and `ext-boringssl` for TLS connections where you need fine-grained control.

```ini
extension=openssl.so
extension=boringssl.so
```

## Migration checklist

1. Choose the OOP or procedural API (or mix both -- they're interchangeable)
2. Replace `stream_context_create(['ssl' => ...])` with context configuration
3. Split `ssl://` connections into TCP connect + `connect()` / `boringssl_connect()`
4. Replace `fread()`/`fwrite()` with `read()`/`write()` or `boringssl_read()`/`boringssl_write()`
5. Replace `fclose()` with `shutdown()` / `boringssl_shutdown()`
6. Wrap handshake and I/O in `try/catch` for `BoringSSL\Exception`
7. Remove `setCipherSuites()` calls (or accept the E_NOTICE)
8. If you relied on `verify_peer_name`, add manual hostname verification until SNI support is added
9. Move session management from implicit (ext-openssl) to explicit (`getSession()`/`setSession()` or `boringssl_get_session()`/`boringssl_set_session()`)
