--TEST--
HTTP/2 keep-alive with multiple streams - mirrors HTTPSocket socket pool reuse
--EXTENSIONS--
boringssl
hpack
brotli
zstd
--FILE--
<?php
// Replicates HTTPSocket's H2 keep-alive behavior:
// Single TLS connection, multiple requests on odd-numbered streams (1, 3, 5)
// Each request increments lastStreamId by 2

define('PREFACE', "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
define('END_STREAM', 0x01);
define('END_HEADERS', 0x04);
define('DATA_FRAME', 0x00);
define('HEADERS_FRAME', 0x01);
define('SETTINGS_FRAME', 0x04);
define('PING_FRAME', 0x06);
define('GOAWAY_FRAME', 0x07);
define('WINDOW_UPDATE_FRAME', 0x08);
define('RST_STREAM_FRAME', 0x03);

function h2f($type, $flags, $stream, $data = '') {
    return substr(pack("NccN", strlen($data), $type, $flags, $stream), 1) . $data;
}

function readF($conn) {
    $h = boringssl_read($conn, 9);
    if (!$h || strlen($h) < 9) return false;
    $f = unpack("Nlength/ctype/cflags/NstreamId", "\x00" . $h);
    $f['payload'] = '';
    $r = $f['length'];
    while ($r > 0) {
        $c = boringssl_read($conn, $r);
        if ($c === false || $c === '') break;
        $f['payload'] .= $c; $r -= strlen($c);
    }
    return $f;
}

function doH2Request($conn, $hpack, $streamId, $path) {
    $headers = [
        [':method', 'GET'],
        [':authority', 'www.google.com'],
        [':scheme', 'https'],
        [':path', $path],
        ['user-agent', 'php-boringssl-test/1.0'],
        ['accept', '*/*'],
        ['accept-encoding', 'gzip, deflate, br, zstd'],
    ];
    boringssl_write($conn, h2f(HEADERS_FRAME, END_HEADERS | END_STREAM, $streamId, $hpack->encode($headers)));

    $code = null; $body = ''; $done = false;
    $start = microtime(true);
    while (!$done && (microtime(true) - $start) < 10) {
        $f = readF($conn);
        if (!$f) break;
        if ($f['type'] == SETTINGS_FRAME && !$f['flags']) {
            boringssl_write($conn, h2f(SETTINGS_FRAME, 1, 0));
        } elseif ($f['type'] == PING_FRAME && !$f['flags']) {
            boringssl_write($conn, h2f(PING_FRAME, 1, 0, $f['payload']));
        } elseif ($f['type'] == HEADERS_FRAME && $f['streamId'] == $streamId) {
            $dec = $hpack->decode($f['payload'], 65535);
            foreach ($dec as $h) { if ($h[0] === ':status') $code = $h[1]; }
            if ($f['flags'] & END_STREAM) $done = true;
        } elseif ($f['type'] == DATA_FRAME && $f['streamId'] == $streamId) {
            $body .= $f['payload'];
            if ($f['flags'] & END_STREAM) $done = true;
        } elseif ($f['type'] == GOAWAY_FRAME) {
            break;
        }
    }
    return ['code' => $code, 'bodyLen' => strlen($body)];
}

// TLS connect
$ctx = boringssl_context_new();
boringssl_context_set_min_proto_version($ctx, BoringSSL\TLS1_2_VERSION);
boringssl_context_set_max_proto_version($ctx, BoringSSL\TLS1_3_VERSION);
boringssl_context_set_groups_list($ctx, 'X25519:P-256');
boringssl_context_set_grease($ctx, true);
boringssl_context_set_alpn_protos($ctx, ['h2', 'http/1.1']);

$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn = boringssl_new_connection($ctx);
boringssl_set_stream($conn, $tcp);
boringssl_connect($conn);
echo "TLS connected\n";

// H2 preface
$settings = '';
foreach ([0x02 => 1, 0x03 => 256, 0x04 => 6291456, 0x05 => 16384] as $k => $v)
    $settings .= pack('nN', $k, $v);
boringssl_write($conn, PREFACE . h2f(SETTINGS_FRAME, 0, 0, $settings) . h2f(WINDOW_UPDATE_FRAME, 0, 0, pack('N', 15663105)));

$hpack = new HPackContext();

// Stream IDs must be odd and increment (HTTPSocket: lastStreamId += 2, starts at -1)
$lastStreamId = -1;
$paths = ['/', '/robots.txt', '/favicon.ico'];

foreach ($paths as $i => $path) {
    $lastStreamId += 2;
    $result = doH2Request($conn, $hpack, $lastStreamId, $path);
    echo "Stream $lastStreamId ($path): code={$result['code']} body={$result['bodyLen']}b\n";
}

echo "Requests on single connection: " . count($paths) . "\n";
echo "Final stream ID: $lastStreamId\n";

boringssl_shutdown($conn);
fclose($tcp);
echo "H2 keep-alive test passed\n";
?>
--EXPECTF--
TLS connected
Stream 1 (/): code=200 body=%db
Stream 3 (/robots.txt): code=200 body=%db
Stream 5 (/favicon.ico): code=200 body=%db
Requests on single connection: 3
Final stream ID: 5
H2 keep-alive test passed
