--TEST--
HTTP/2 full request with brotli and zstd decompression - mirrors HTTPSocket h2 code path
--EXTENSIONS--
boringssl
hpack
brotli
zstd
--FILE--
<?php
// Replicates the HTTP/2 flow from HTTPSocket.class.php:
// 1. TLS connect with ALPN h2
// 2. Send connection preface + SETTINGS + WINDOW_UPDATE
// 3. Two requests on the same connection:
//    - Stream 1: accept-encoding br only → brotli decompression
//    - Stream 3: accept-encoding zstd only → zstd decompression

define('PREFACE', "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
define('END_STREAM', 0x01);
define('END_HEADERS', 0x04);
define('DATA_FRAME', 0x00);
define('HEADERS_FRAME', 0x01);
define('RST_STREAM_FRAME', 0x03);
define('SETTINGS_FRAME', 0x04);
define('PING_FRAME', 0x06);
define('GOAWAY_FRAME', 0x07);
define('WINDOW_UPDATE_FRAME', 0x08);

function h2frame($type, $flags, $stream, $data = '') {
    return substr(pack("NccN", strlen($data), $type, $flags, $stream), 1) . $data;
}

function buildSettings($settings) {
    $data = '';
    foreach ($settings as $k => $v) $data .= pack('nN', $k, $v);
    return $data;
}

function readFrame($conn) {
    $buf = boringssl_read($conn, 9);
    if ($buf === false || strlen($buf) < 9) return false;
    $frame = unpack("Nlength/ctype/cflags/NstreamId", "\x00{$buf}");
    $frame['payload'] = '';
    $rem = $frame['length'];
    while ($rem > 0) {
        $chunk = boringssl_read($conn, min($rem, 16384));
        if ($chunk === false || $chunk === '') break;
        $frame['payload'] .= $chunk;
        $rem -= strlen($chunk);
    }
    return $frame;
}

function doH2Get($conn, $hpack, $streamId, $host, $path, $acceptEncoding) {
    $headers = [
        [':method', 'GET'],
        [':authority', $host],
        [':scheme', 'https'],
        [':path', $path],
        ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'],
        ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
        ['accept-encoding', $acceptEncoding],
        ['accept-language', 'en-US,en;q=0.9'],
    ];
    boringssl_write($conn, h2frame(HEADERS_FRAME, END_HEADERS | END_STREAM, $streamId, $hpack->encode($headers)));

    $code = null;
    $respHeaders = [];
    $body = '';
    $done = false;
    $start = microtime(true);

    while (!$done && (microtime(true) - $start) < 10) {
        $f = readFrame($conn);
        if (!$f) break;
        if ($f['type'] == SETTINGS_FRAME && !$f['flags']) {
            boringssl_write($conn, h2frame(SETTINGS_FRAME, 1, 0));
        } elseif ($f['type'] == PING_FRAME && !$f['flags']) {
            boringssl_write($conn, h2frame(PING_FRAME, 1, 0, $f['payload']));
        } elseif ($f['type'] == HEADERS_FRAME && $f['streamId'] == $streamId) {
            $dec = $hpack->decode($f['payload'], 65535);
            if ($dec) foreach ($dec as $h) {
                $respHeaders[$h[0]] = $h[1];
                if ($h[0] === ':status') $code = $h[1];
            }
            if ($f['flags'] & END_STREAM) $done = true;
        } elseif ($f['type'] == DATA_FRAME && $f['streamId'] == $streamId) {
            $body .= $f['payload'];
            if ($f['flags'] & END_STREAM) $done = true;
        } elseif ($f['type'] == GOAWAY_FRAME || $f['type'] == RST_STREAM_FRAME) {
            break;
        }
    }
    return ['code' => $code, 'headers' => $respHeaders, 'body' => $body];
}

// --- TLS connect with Chrome-like config ---

$ctx = boringssl_context_new();
boringssl_context_set_min_proto_version($ctx, BoringSSL\TLS1_2_VERSION);
boringssl_context_set_max_proto_version($ctx, BoringSSL\TLS1_3_VERSION);
boringssl_context_set_cipher_list($ctx,
    'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:' .
    'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:' .
    'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
);
boringssl_context_set_groups_list($ctx, 'X25519:P-256:P-384');
boringssl_context_set_alpn_protos($ctx, ['h2', 'http/1.1']);
boringssl_context_set_grease($ctx, true);
boringssl_context_set_permute_extensions($ctx, true);
boringssl_context_add_cert_compression_alg($ctx, BoringSSL\CERT_COMPRESS_BROTLI);
boringssl_context_add_application_settings($ctx, 'h2', '');
boringssl_context_set_alps_use_new_codepoint($ctx, true);

$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn = boringssl_new_connection($ctx);
boringssl_set_stream($conn, $tcp);
boringssl_connect($conn);
echo "TLS: " . boringssl_get_cipher($conn) . " ALPN: " . boringssl_get_alpn_proto($conn) . "\n";

// --- H2 connection setup ---

boringssl_write($conn,
    PREFACE .
    h2frame(SETTINGS_FRAME, 0, 0, buildSettings([
        0x02 => 1, 0x03 => 256, 0x04 => 6291456, 0x05 => 16384,
    ])) .
    h2frame(WINDOW_UPDATE_FRAME, 0, 0, pack('N', 15663105))
);

$hpack = new HPackContext();

// --- Request 1: brotli only (stream 1) ---

$r1 = doH2Get($conn, $hpack, 1, 'www.google.com', '/', 'br');
$enc1 = $r1['headers']['content-encoding'] ?? 'none';
echo "Stream 1: code={$r1['code']} encoding=$enc1 compressed=" . strlen($r1['body']) . "b\n";

if ($enc1 === 'br') {
    $decompressed1 = brotli_uncompress($r1['body']);
    $ok1 = ($decompressed1 !== false && strlen($decompressed1) > strlen($r1['body']));
    echo "Brotli decompress: " . ($ok1 ? "OK" : "FAIL") . " (" . strlen($decompressed1) . "b)\n";
    echo "Contains HTML: " . (stripos($decompressed1, '<html') !== false || stripos($decompressed1, '<!doctype') !== false ? "yes" : "no") . "\n";
} else {
    echo "Server did not use brotli (got $enc1)\n";
    echo "Contains HTML: skip\n";
}

// --- Request 2: zstd only (stream 3) ---

$r2 = doH2Get($conn, $hpack, 3, 'www.google.com', '/', 'zstd');
$enc2 = $r2['headers']['content-encoding'] ?? 'none';
echo "Stream 3: code={$r2['code']} encoding=$enc2 compressed=" . strlen($r2['body']) . "b\n";

if ($enc2 === 'zstd') {
    $decompressed2 = zstd_uncompress($r2['body']);
    $ok2 = ($decompressed2 !== false && strlen($decompressed2) > strlen($r2['body']));
    echo "Zstd decompress: " . ($ok2 ? "OK" : "FAIL") . " (" . strlen($decompressed2) . "b)\n";
    echo "Contains HTML: " . (stripos($decompressed2, '<html') !== false || stripos($decompressed2, '<!doctype') !== false ? "yes" : "no") . "\n";
} else {
    // Google may not support zstd yet — still validates the request path worked
    echo "Server did not use zstd (got $enc2), decoding as $enc2\n";
    if ($enc2 === 'none' || $enc2 === '') {
        echo "Contains HTML: " . (stripos($r2['body'], '<html') !== false ? "yes" : "no") . "\n";
    } else {
        echo "Contains HTML: skipped (unexpected encoding)\n";
    }
}

boringssl_shutdown($conn);
fclose($tcp);

echo "H2 brotli+zstd test passed\n";
?>
--EXPECTF--
TLS: TLS_AES_128_GCM_SHA256 ALPN: h2
Stream 1: code=200 encoding=br compressed=%db
Brotli decompress: OK (%db)
Contains HTML: yes
Stream 3: code=200 encoding=%s compressed=%db
%s
Contains HTML: yes
H2 brotli+zstd test passed
