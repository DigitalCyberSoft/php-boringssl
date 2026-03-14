--TEST--
Bidirectional I/O - interleaved reads and writes
--EXTENSIONS--
boringssl
--FILE--
<?php
$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256');

// Test 1: Interleaved small writes (write request in parts)
$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn = $ctx->newConnection()->setStream($tcp);
$conn->connect();

$w1 = $conn->write("GET / HTTP");
$w2 = $conn->write("/1.1\r\n");
$w3 = $conn->write("Host: www.google.com\r\n");
$w4 = $conn->write("Connection: close\r\n");
$w5 = $conn->write("\r\n");

$total = $w1 + $w2 + $w3 + $w4 + $w5;
echo "Partial writes: $total bytes total\n";
echo "Each write returned > 0: " . (min($w1,$w2,$w3,$w4,$w5) > 0 ? "yes" : "FAIL") . "\n";

$resp = $conn->read(128);
echo "After partial writes: " . strtok($resp, "\r\n") . "\n";
$conn->shutdown();
fclose($tcp);

// Test 2: Read exact small byte counts
$tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn2 = $ctx->newConnection()->setStream($tcp2);
$conn2->connect();

$conn2->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");

// Read 4 bytes at a time
$small_reads = '';
for ($i = 0; $i < 4; $i++) {
    $chunk = $conn2->read(4);
    if ($chunk === false || $chunk === '') break;
    $small_reads .= $chunk;
}
echo "Small reads result: \"" . substr($small_reads, 0, 15) . "\"\n";
echo "Got 16 bytes: " . (strlen($small_reads) >= 15 ? "yes" : "no (" . strlen($small_reads) . ")") . "\n";
$conn2->shutdown();
fclose($tcp2);

// Test 3: Write then read, write then read (interleaved)
$tcp3 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn3 = $ctx->newConnection()->setStream($tcp3);
$conn3->connect();

// First write+read
$conn3->write("HEAD / HTTP/1.1\r\nHost: www.google.com\r\n\r\n");
$resp1 = $conn3->read(4096);
$line1 = strtok($resp1, "\r\n");
echo "Interleaved req 1: $line1\n";

// Second write+read (keep-alive)
$conn3->write("HEAD /robots.txt HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
$resp2 = $conn3->read(4096);
// Response may include tail of previous response
echo "Interleaved req 2: got " . strlen($resp2) . " bytes\n";
echo "Interleaved req 2: contains HTTP: " . (strpos($resp2, 'HTTP/') !== false ? "yes" : "no") . "\n";

$conn3->shutdown();
fclose($tcp3);

// Test 4: pending() check
$tcp4 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn4 = $ctx->newConnection()->setStream($tcp4);
$conn4->connect();

$conn4->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
// Give server time to respond
$first = $conn4->read(16);
$pending = $conn4->pending();
echo "After partial read, pending: " . ($pending >= 0 ? "valid ($pending bytes)" : "FAIL") . "\n";

$conn4->shutdown();
fclose($tcp4);

echo "Bidirectional I/O tests passed\n";
?>
--EXPECTF--
Partial writes: %d bytes total
Each write returned > 0: yes
After partial writes: HTTP/1.1 200 OK
Small reads result: "HTTP/1.1 200 OK"
Got 16 bytes: yes
Interleaved req 1: HTTP/1.1 200 OK
Interleaved req 2: got %d bytes
Interleaved req 2: contains HTTP: yes
After partial read, pending: valid (%d bytes)
Bidirectional I/O tests passed
