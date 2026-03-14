--TEST--
HTTP/2 POST request with body - mirrors HTTPSocket h2 data frame path
--EXTENSIONS--
boringssl
hpack
brotli
zstd
--FILE--
<?php
// Replicates HTTPSocket's H2 POST flow:
// HEADERS frame (without END_STREAM) + DATA frame(s) with body + END_STREAM

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

function h2frame($type, $flags, $stream, $data = '') {
    return substr(pack("NccN", strlen($data), $type, $flags, $stream), 1) . $data;
}

function readFrame($conn) {
    $hdr = boringssl_read($conn, 9);
    if (!$hdr || strlen($hdr) < 9) return false;
    $f = unpack("Nlength/ctype/cflags/NstreamId", "\x00" . $hdr);
    $f['payload'] = '';
    $rem = $f['length'];
    while ($rem > 0) {
        $c = boringssl_read($conn, $rem);
        if ($c === false || $c === '') break;
        $f['payload'] .= $c;
        $rem -= strlen($c);
    }
    return $f;
}

// Replicates HTTPSocket::sendH2Data - split body across frames
function sendH2Data($conn, $streamId, $body, $maxFrameSize) {
    while (strlen($body) > $maxFrameSize) {
        $chunk = substr($body, 0, $maxFrameSize);
        $body = substr($body, $maxFrameSize);
        boringssl_write($conn, h2frame(DATA_FRAME, 0, $streamId, $chunk));
    }
    boringssl_write($conn, h2frame(DATA_FRAME, END_STREAM, $streamId, $body));
}

// TLS setup
$ctx = boringssl_context_new();
boringssl_context_set_min_proto_version($ctx, BoringSSL\TLS1_2_VERSION);
boringssl_context_set_max_proto_version($ctx, BoringSSL\TLS1_3_VERSION);
boringssl_context_set_groups_list($ctx, 'X25519:P-256');
boringssl_context_set_grease($ctx, true);
boringssl_context_set_permute_extensions($ctx, true);
boringssl_context_add_cert_compression_alg($ctx, BoringSSL\CERT_COMPRESS_BROTLI);
boringssl_context_set_alpn_protos($ctx, ['h2', 'http/1.1']);

$tcp = stream_socket_client('tcp://httpbin.org:443', $errno, $errstr, 10);
$conn = boringssl_new_connection($ctx);
boringssl_set_stream($conn, $tcp);
boringssl_connect($conn);
echo "TLS connected\n";

// H2 connection preface
$initData = PREFACE;
$settings = '';
foreach ([0x02 => 1, 0x03 => 256, 0x04 => 6291456, 0x05 => 16384] as $k => $v)
    $settings .= pack('nN', $k, $v);
$initData .= h2frame(SETTINGS_FRAME, 0, 0, $settings);
$initData .= h2frame(WINDOW_UPDATE_FRAME, 0, 0, pack('N', 15663105));
boringssl_write($conn, $initData);

// Build POST request headers
$hpack = new HPackContext();
$postBody = 'hello=world&test=boringssl'; // 26 bytes
$h2Headers = [
    [':method', 'POST'],
    [':authority', 'httpbin.org'],
    [':scheme', 'https'],
    [':path', '/post'],
    ['user-agent', 'php-boringssl-test/1.0'],
    ['accept', '*/*'],
    ['accept-encoding', 'gzip, deflate, br, zstd'],
    ['content-type', 'application/x-www-form-urlencoded'],
    ['content-length', (string)strlen($postBody)],
];

$streamId = 1;
$encoded = $hpack->encode($h2Headers);

// HEADERS frame WITHOUT END_STREAM (body follows)
boringssl_write($conn, h2frame(HEADERS_FRAME, END_HEADERS, $streamId, $encoded));
echo "HEADERS sent (no END_STREAM)\n";

// DATA frame with END_STREAM
sendH2Data($conn, $streamId, $postBody, 16384);
echo "DATA sent with POST body (" . strlen($postBody) . " bytes)\n";

// Read response
$responseCode = null;
$responseBody = '';
$done = false;
$start = microtime(true);

while (!$done && (microtime(true) - $start) < 15) {
    $f = readFrame($conn);
    if (!$f) break;

    if ($f['type'] == SETTINGS_FRAME && !$f['flags']) {
        boringssl_write($conn, h2frame(SETTINGS_FRAME, 1, 0));
    } elseif ($f['type'] == PING_FRAME && !$f['flags']) {
        boringssl_write($conn, h2frame(PING_FRAME, 1, 0, $f['payload']));
    } elseif ($f['type'] == HEADERS_FRAME && $f['streamId'] == $streamId) {
        $decoded = $hpack->decode($f['payload'], 65535);
        foreach ($decoded as $h) {
            if ($h[0] === ':status') $responseCode = $h[1];
        }
        if ($f['flags'] & END_STREAM) $done = true;
    } elseif ($f['type'] == DATA_FRAME && $f['streamId'] == $streamId) {
        $responseBody .= $f['payload'];
        if ($f['flags'] & END_STREAM) $done = true;
    } elseif ($f['type'] == RST_STREAM_FRAME || $f['type'] == GOAWAY_FRAME) {
        break;
    }
}

echo "Response code: $responseCode\n";

// Decompress (handle zstd, brotli, gzip, or uncompressed)
$decoded = @zstd_uncompress($responseBody);
if ($decoded !== false) $responseBody = $decoded;
else {
    $decoded = @brotli_uncompress($responseBody);
    if ($decoded !== false) $responseBody = $decoded;
    else {
        $decoded = @gzdecode($responseBody);
        if ($decoded !== false) $responseBody = $decoded;
    }
}

// httpbin.org /post returns JSON with the form data
$json = json_decode($responseBody, true);
if ($json && isset($json['form'])) {
    echo "Form data echoed back:\n";
    echo "  hello=" . ($json['form']['hello'] ?? 'MISSING') . "\n";
    echo "  test=" . ($json['form']['test'] ?? 'MISSING') . "\n";
} else {
    echo "Response body (" . strlen($responseBody) . " bytes)\n";
    echo "Contains 'hello': " . (strpos($responseBody, 'hello') !== false ? "yes" : "no") . "\n";
}

boringssl_shutdown($conn);
fclose($tcp);
echo "H2 POST test passed\n";
?>
--EXPECTF--
TLS connected
HEADERS sent (no END_STREAM)
DATA sent with POST body (%d bytes)
Response code: 200
Form data echoed back:
  hello=world
  test=boringssl
H2 POST test passed
