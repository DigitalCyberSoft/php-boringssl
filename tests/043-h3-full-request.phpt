--TEST--
HTTP/3 full request via BoringSSL QUIC (ngtcp2) - mirrors HTTPSocket h3 code path
--EXTENSIONS--
boringssl
qpack
brotli
zstd
--FILE--
<?php
// Replicates the HTTP/3 flow from HTTPSocket.class.php using the
// BoringSSL extension's native QUIC transport (ngtcp2 + BoringSSL).

function ev(int $v): string {
    if ($v < 64) return chr($v);
    if ($v < 16384) return pack('n', 0x4000 | $v);
    if ($v < 1073741824) return pack('N', 0x80000000 | $v);
    return pack('J', 0xC000000000000000 | $v);
}

function dv(string $d, int &$o): int {
    $f = ord($d[$o]); $p = $f >> 6;
    switch ($p) {
        case 0: $o++; return $f & 0x3F;
        case 1: $v = unpack('n', substr($d, $o, 2))[1] & 0x3FFF; $o += 2; return $v;
        case 2: $v = unpack('N', substr($d, $o, 4))[1] & 0x3FFFFFFF; $o += 4; return $v;
        case 3: $v = unpack('J', substr($d, $o, 8))[1] & 0x3FFFFFFFFFFFFFFF; $o += 8; return $v;
    }
}

// --- QUIC connect via BoringSSL ngtcp2 transport ---

$conn = boringssl_quic_connect('www.google.com', 443, [
    'alpn' => ['h3'],
    'timeout' => 10,
]);
echo "QUIC connected: " . ($conn->isConnected() ? "yes" : "no") . "\n";
echo "ALPN: " . $conn->getAlpn() . "\n";

// --- H3 setup (control + QPACK streams) ---

$ctrl = boringssl_quic_open_stream($conn, BoringSSL\QUIC_STREAM_UNI);
boringssl_quic_stream_write($ctrl, ev(0x00));
$greaseIds = [0x0b, 0x1b, 0x2b, 0x3b, 0x4b, 0x5b, 0x6b, 0x7b];
$sp = ev($greaseIds[array_rand($greaseIds)]) . ev(0)
    . ev(0x01) . ev(0) . ev(0x06) . ev(262144) . ev(0x07) . ev(100);
boringssl_quic_stream_write($ctrl, ev(0x04) . ev(strlen($sp)) . $sp);

$qe = boringssl_quic_open_stream($conn, BoringSSL\QUIC_STREAM_UNI);
boringssl_quic_stream_write($qe, ev(0x02));
$qd = boringssl_quic_open_stream($conn, BoringSSL\QUIC_STREAM_UNI);
boringssl_quic_stream_write($qd, ev(0x03));

$qpack = new QPackContext(0, 100);
echo "H3 setup complete\n";

// --- Send request ---

$h3Headers = $qpack->encode([
    [':method', 'GET'], [':authority', 'www.google.com'],
    [':scheme', 'https'], [':path', '/'],
    ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'],
    ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
    ['accept-encoding', 'gzip, deflate, br, zstd'],
    ['accept-language', 'en-US,en;q=0.9'],
]);

$req = boringssl_quic_open_stream($conn, BoringSSL\QUIC_STREAM_BIDI);
boringssl_quic_stream_write($req, ev(0x01) . ev(strlen($h3Headers)) . $h3Headers);
boringssl_quic_stream_conclude($req);
echo "H3 request sent\n";

// --- Read response ---

$buf = '';
$start = microtime(true);
while (microtime(true) - $start < 15) {
    $chunk = boringssl_quic_stream_read($req, 0, 100);
    if ($chunk === null) break;
    if ($chunk === false) { usleep(50000); continue; }
    $buf .= $chunk;
}
echo "Raw response: " . strlen($buf) . " bytes\n";

// Parse H3 frames
$code = null; $headers = []; $body = '';
$o = 0; $bl = strlen($buf);
while ($o < $bl) {
    $ft = dv($buf, $o); $fl = dv($buf, $o);
    if ($o + $fl > $bl) { $body .= substr($buf, $o); break; }
    $fd = substr($buf, $o, $fl); $o += $fl;
    if ($ft == 0x01) {
        $d = $qpack->decode($fd, 65535);
        if ($d) foreach ($d as $h) { $headers[$h[0]] = $h[1]; if ($h[0] === ':status') $code = $h[1]; }
    } elseif ($ft == 0x00) {
        $body .= $fd;
    }
}

echo "Status: $code\n";
$enc = $headers['content-encoding'] ?? 'none';
echo "Encoding: $enc\n";
echo "Body: " . strlen($body) . " bytes\n";

// Decompress
$html = $body;
if (strpos($enc, 'zstd') !== false) {
    $html = zstd_uncompress($body); echo "Decompressed: zstd\n";
} elseif (strpos($enc, 'br') !== false) {
    $html = brotli_uncompress($body); echo "Decompressed: brotli\n";
} elseif (strpos($enc, 'gzip') !== false) {
    $html = gzdecode($body); echo "Decompressed: gzip\n";
} else {
    echo "Decompressed: identity\n";
}

if ($html === false || $html === null) $html = $body;
echo "Contains HTML: " . (stripos($html, '<!doctype') !== false || stripos($html, '<html') !== false ? "yes" : "no") . "\n";

boringssl_quic_close($conn);
echo "H3 test passed\n";
?>
--EXPECTF--
QUIC connected: yes
ALPN: h3
H3 setup complete
H3 request sent
Raw response: %d bytes
Status: 200
Encoding: %s
Body: %d bytes
Decompressed: %s
Contains HTML: yes
H3 test passed
