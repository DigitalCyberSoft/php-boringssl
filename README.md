# php-boringssl

A PHP extension providing direct access to Google's [BoringSSL](https://boringssl.googlesource.com/boringssl/) library. Exposes BoringSSL-specific TLS features that are unavailable through PHP's built-in OpenSSL extension, including GREASE, extension permutation, certificate compression, ALPS, Encrypted Client Hello (ECH), post-quantum key exchange, and TLS fingerprint control.

## Requirements

- PHP 8.1+
- BoringSSL (built from source)
- Linux (x86_64 or aarch64)

### Optional (for certificate compression)

- libbrotli (`brotli/encode.h`, `brotli/decode.h`)
- zlib (`zlib.h`)
- libzstd (`zstd.h`)

## Building

### 1. Build BoringSSL

```bash
git clone https://boringssl.googlesource.com/boringssl
cd boringssl
mkdir build && cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make -j$(nproc)
cd ../..
```

### 2. Build ngtcp2 with BoringSSL (optional, for QUIC support)

```bash
git clone --branch v1.15.1 https://github.com/ngtcp2/ngtcp2.git deps/ngtcp2
cd deps/ngtcp2 && mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DENABLE_BORINGSSL=ON \
  -DBORINGSSL_INCLUDE_DIR=../../boringssl/include \
  -DBORINGSSL_LIBRARIES="../../boringssl/build/libssl.a;../../boringssl/build/libcrypto.a" \
  -DENABLE_GNUTLS=OFF -DENABLE_OPENSSL=OFF -DBUILD_TESTING=OFF ..
ninja ngtcp2_static ngtcp2_crypto_boringssl_static
cd ../../..
```

### 3. Build the extension

```bash
phpize
./configure --with-boringssl=/path/to/boringssl
make
make install
```

QUIC support is auto-detected: if ngtcp2 is found in `deps/ngtcp2/build/`, it is statically linked and QUIC classes/functions are enabled.

Add to your `php.ini`:

```ini
extension=boringssl.so
```

Verify:

```bash
php -m | grep boringssl
php --ri boringssl
```

## Quick start

The extension provides both an object-oriented API and a procedural API. Both are fully supported.

### Object-oriented

```php
$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256');

$tcp = stream_socket_client('tcp://example.com:443', $errno, $errstr, 10);
$conn = $ctx->newConnection()->setStream($tcp);
$conn->connect();

$conn->write("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
$response = $conn->read(4096);

$conn->shutdown();
```

### Procedural

```php
$ctx = boringssl_context_new();
boringssl_context_set_min_proto_version($ctx, BoringSSL\TLS1_3_VERSION);
boringssl_context_set_max_proto_version($ctx, BoringSSL\TLS1_3_VERSION);
boringssl_context_set_groups_list($ctx, 'X25519:P-256');

$tcp = stream_socket_client('tcp://example.com:443', $errno, $errstr, 10);
$conn = boringssl_new_connection($ctx);
boringssl_set_stream($conn, $tcp);
boringssl_connect($conn);

boringssl_write($conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
$response = boringssl_read($conn, 4096);

boringssl_shutdown($conn);
```

### QUIC / HTTP/3

```php
// QUIC connect (ngtcp2 + BoringSSL, same TLS stack as Chrome)
$conn = boringssl_quic_connect('example.com', 443, ['alpn' => ['h3']]);

$stream = boringssl_quic_open_stream($conn, BoringSSL\QUIC_STREAM_BIDI);
boringssl_quic_stream_write($stream, $request_data);
boringssl_quic_stream_conclude($stream);

$response = boringssl_quic_stream_read($stream);
boringssl_quic_close($conn);
```

## Scope and limitations

This extension exposes BoringSSL's TLS and QUIC primitives to PHP. It is **not** a drop-in Chrome TLS stack. Browser-level behaviors that depend on Chrome's networking internals rather than BoringSSL itself are out of scope:

- **Chrome's internal session ticket rotation** and cache eviction logic
- **Delegated credentials** (RFC 9345)
- **Certificate Transparency** (SCT) policy enforcement
- **Chrome's built-in CA root store** and CRLSets
- **Platform-specific certificate verification** (NSS, Keychain, Windows CryptoAPI)
- **Channel ID / Token Binding** (deprecated)

The extension gives you the building blocks. Replicating higher-level browser behavior from those blocks is application-level work.

## API overview

### Classes (OOP API)

| Class | Description |
|---|---|
| `BoringSSL\Context` | SSL context configuration (wraps `SSL_CTX`) |
| `BoringSSL\Connection` | A single TLS connection (wraps `SSL`) |
| `BoringSSL\Session` | Serializable TLS session for resumption |
| `BoringSSL\QuicConnection` | QUIC transport connection (ngtcp2 + BoringSSL) |
| `BoringSSL\QuicStream` | A QUIC stream (bidirectional or unidirectional) |
| `BoringSSL\Exception` | Thrown on TLS errors (extends `RuntimeException`) |

### Procedural functions

Every OOP method has a procedural equivalent. Context and connection objects are passed as the first argument instead of using `$this`.

| Function | OOP equivalent |
|---|---|
| `boringssl_context_new()` | `(new Context)->new()` |
| `boringssl_context_new_server()` | `(new Context)->newServer()` |
| `boringssl_context_set_cipher_list($ctx, $ciphers)` | `$ctx->setCipherList($ciphers)` |
| `boringssl_context_set_alpn_protos($ctx, $protocols)` | `$ctx->setAlpnProtos($protocols)` |
| `boringssl_context_set_groups_list($ctx, $groups)` | `$ctx->setGroupsList($groups)` |
| `boringssl_context_set_verify_algorithm_prefs($ctx, $ids)` | `$ctx->setVerifyAlgorithmPrefs($ids)` |
| `boringssl_context_set_signing_algorithm_prefs($ctx, $ids)` | `$ctx->setSigningAlgorithmPrefs($ids)` |
| `boringssl_context_set_grease($ctx, $enabled)` | `$ctx->setGreaseEnabled($enabled)` |
| `boringssl_context_set_permute_extensions($ctx, $enabled)` | `$ctx->setPermuteExtensions($enabled)` |
| `boringssl_context_add_application_settings($ctx, $proto, $settings)` | `$ctx->addApplicationSettings($proto, $settings)` |
| `boringssl_context_set_alps_use_new_codepoint($ctx, $enabled)` | `$ctx->setAlpsUseNewCodepoint($enabled)` |
| `boringssl_context_add_cert_compression_alg($ctx, $algId)` | `$ctx->addCertCompressionAlg($algId)` |
| `boringssl_context_set_ech_config_list($ctx, $config)` | `$ctx->setEchConfigList($config)` |
| `boringssl_context_set_min_proto_version($ctx, $version)` | `$ctx->setMinProtoVersion($version)` |
| `boringssl_context_set_max_proto_version($ctx, $version)` | `$ctx->setMaxProtoVersion($version)` |
| `boringssl_context_set_early_data($ctx, $enabled)` | `$ctx->setEarlyDataEnabled($enabled)` |
| `boringssl_context_use_certificate_file($ctx, $path)` | `$ctx->useCertificateFile($path)` |
| `boringssl_context_use_private_key_file($ctx, $path)` | `$ctx->usePrivateKeyFile($path)` |
| `boringssl_context_load_verify_locations($ctx, $caFile [, $caPath])` | `$ctx->loadVerifyLocations($caFile, $caPath)` |
| `boringssl_context_set_verify($ctx, $mode)` | `$ctx->setVerify($mode)` |
| `boringssl_context_set_default_verify_paths($ctx)` | `$ctx->setDefaultVerifyPaths()` |
| `boringssl_context_set_verify_depth($ctx, $depth)` | `$ctx->setVerifyDepth($depth)` |
| `boringssl_context_set_options($ctx, $options)` | `$ctx->setOptions($options)` |
| `boringssl_context_clear_options($ctx, $options)` | `$ctx->clearOptions($options)` |
| `boringssl_context_get_options($ctx)` | `$ctx->getOptions()` |
| `boringssl_context_enable_ocsp_stapling($ctx, $enabled)` | `$ctx->enableOcspStapling($enabled)` |
| `boringssl_context_enable_signed_cert_timestamps($ctx, $enabled)` | `$ctx->enableSignedCertTimestamps($enabled)` |
| `boringssl_context_set_keylog_file($ctx, $path)` | `$ctx->setKeylogFile($path)` |
| `boringssl_context_load_client_ca_file($ctx, $path)` | `$ctx->loadClientCAFile($path)` |
| `boringssl_context_set_session_ticket_keys($ctx, $keys)` | `$ctx->setSessionTicketKeys($keys)` |
| `boringssl_context_use_certificate_chain_pem($ctx, $pem)` | `$ctx->useCertificateChainPem($pem)` |
| `boringssl_context_use_private_key_pem($ctx, $pem)` | `$ctx->usePrivateKeyPem($pem)` |
| `boringssl_new_connection($ctx)` | `$ctx->newConnection()` |
| `boringssl_set_fd($conn, $fd)` | `$conn->setFd($fd)` |
| `boringssl_set_stream($conn, $stream)` | `$conn->setStream($stream)` |
| `boringssl_connect($conn)` | `$conn->connect()` |
| `boringssl_accept($conn)` | `$conn->accept()` |
| `boringssl_read($conn, $length)` | `$conn->read($length)` |
| `boringssl_write($conn, $data)` | `$conn->write($data)` |
| `boringssl_pending($conn)` | `$conn->pending()` |
| `boringssl_shutdown($conn)` | `$conn->shutdown()` |
| `boringssl_get_cipher($conn)` | `$conn->getNegotiatedCipher()` |
| `boringssl_get_alpn_proto($conn)` | `$conn->getNegotiatedAlpn()` |
| `boringssl_get_group($conn)` | `$conn->getNegotiatedGroup()` |
| `boringssl_get_version($conn)` | `$conn->getProtocolVersion()` |
| `boringssl_get_session($conn)` | `$conn->getSession()` |
| `boringssl_set_session($conn, $session)` | `$conn->setSession($session)` |
| `boringssl_set_hostname($conn, $hostname)` | `$conn->setHostname($hostname)` |
| `boringssl_get_verify_result($conn)` | `$conn->getVerifyResult()` |
| `boringssl_session_reused($conn)` | `$conn->isSessionReused()` |
| `boringssl_peek($conn, $length)` | `$conn->peek($length)` |
| `boringssl_key_update($conn)` | `$conn->keyUpdate()` |
| `boringssl_get_ocsp_response($conn)` | `$conn->getOcspResponse()` |
| `boringssl_get_signed_cert_timestamps($conn)` | `$conn->getSignedCertTimestamps()` |
| `boringssl_get_peer_certificate($conn)` | `$conn->getPeerCertificate()` |
| `boringssl_get_peer_certificate_chain($conn)` | `$conn->getPeerCertificateChain()` |
| `boringssl_export_keying_material($conn, $label, $len, $ctx)` | `$conn->exportKeyingMaterial($label, $len, $ctx)` |
| `boringssl_set_renegotiate_mode($conn, $mode)` | `$conn->setRenegotiateMode($mode)` |
| `boringssl_session_from_bytes($bytes, $ctx)` | `Session::fromBytes($bytes, $ctx)` |
| `boringssl_session_to_bytes($session)` | `$session->toBytes()` |
| `boringssl_session_get_id($session)` | `$session->getId()` |
| `boringssl_session_get_timeout($session)` | `$session->getTimeout()` |
| `boringssl_session_has_ticket($session)` | `$session->hasTicket()` |
| `boringssl_quic_connect($host, $port [, $options])` | `new QuicConnection(...) + connect()` |
| `boringssl_quic_open_stream($conn [, $type])` | `$conn->openStream($type)` |
| `boringssl_quic_stream_write($stream, $data [, $flags])` | `$stream->write($data, $flags)` |
| `boringssl_quic_stream_read($stream [, $length, $timeout])` | `$stream->read($length, $timeout)` |
| `boringssl_quic_stream_conclude($stream)` | `$stream->conclude()` |
| `boringssl_quic_close($conn)` | `$conn->close()` |
| `boringssl_quic_is_connected($conn)` | `$conn->isConnected()` |

### Constants

**Protocol versions:** `TLS1_VERSION`, `TLS1_1_VERSION`, `TLS1_2_VERSION`, `TLS1_3_VERSION`

**Signature algorithms:** `SIGALG_ECDSA_SECP256R1_SHA256`, `SIGALG_RSA_PSS_RSAE_SHA256`, `SIGALG_RSA_PKCS1_SHA256`, `SIGALG_ECDSA_SECP384R1_SHA384`, `SIGALG_RSA_PSS_RSAE_SHA384`, `SIGALG_RSA_PKCS1_SHA384`, `SIGALG_RSA_PSS_RSAE_SHA512`, `SIGALG_RSA_PKCS1_SHA512`, `SIGALG_RSA_PKCS1_SHA1`, `SIGALG_ED25519`

**Certificate compression:** `CERT_COMPRESS_ZLIB`, `CERT_COMPRESS_BROTLI`, `CERT_COMPRESS_ZSTD`

**Verify modes:** `VERIFY_NONE`, `VERIFY_PEER`, `VERIFY_FAIL_IF_NO_CERT`, `VERIFY_CLIENT_ONCE`

**ECH status:** `ECH_STATUS_SUCCESS`, `ECH_STATUS_REJECTED`, `ECH_STATUS_NOT_NEGOTIATED`

**Early data:** `EARLY_DATA_NOT_SENT`, `EARLY_DATA_REJECTED`, `EARLY_DATA_ACCEPTED`

**X509 verification results:** `X509_V_OK`, `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT`, `X509_V_ERR_CERT_NOT_YET_VALID`, `X509_V_ERR_CERT_HAS_EXPIRED`, `X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT`, `X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN`, `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, `X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE`, `X509_V_ERR_CERT_CHAIN_TOO_LONG`, `X509_V_ERR_CERT_REVOKED`, `X509_V_ERR_INVALID_CA`, `X509_V_ERR_HOSTNAME_MISMATCH`

**SSL options:** `SSL_OP_NO_TICKET`, `SSL_OP_CIPHER_SERVER_PREFERENCE`, `SSL_OP_ALL`

**Renegotiation modes:** `RENEGOTIATE_NEVER`, `RENEGOTIATE_ONCE`, `RENEGOTIATE_FREELY`, `RENEGOTIATE_IGNORE`, `RENEGOTIATE_EXPLICIT`

**Session cache modes:** `SESS_CACHE_OFF`, `SESS_CACHE_CLIENT`, `SESS_CACHE_SERVER`, `SESS_CACHE_BOTH`

**QUIC (requires ngtcp2):** `QUIC_STREAM_BIDI`, `QUIC_STREAM_UNI`, `QUIC_WRITE_FLAG_CONCLUDE`

All constants are in the `BoringSSL` namespace.

## License

Licensed under the ISC license (OpenSSL-compatible). BoringSSL itself is licensed under a mix of the ISC license, the OpenSSL license, and the SSLeay license. See the [BoringSSL LICENSE](https://boringssl.googlesource.com/boringssl/+/HEAD/LICENSE) for details.
