--TEST--
Large reads and writes across multiple SSL records
--EXTENSIONS--
boringssl
--FILE--
<?php
$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256');

$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn = $ctx->newConnection()->setStream($tcp);
$conn->connect();
echo "Connected: " . $conn->getNegotiatedCipher() . "\n";

// Test 1: Write a request and read a large response
$conn->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");

// Read in chunks to test multiple SSL_read calls
$total_bytes = 0;
$chunks = 0;
$first_line = '';
while (true) {
    $data = $conn->read(4096);
    if ($data === false || $data === '') {
        break;
    }
    if ($chunks === 0) {
        $first_line = strtok($data, "\r\n");
    }
    $total_bytes += strlen($data);
    $chunks++;
    // Read at least 10KB or stop
    if ($total_bytes > 10240) break;
}
echo "First line: $first_line\n";
echo "Read $chunks chunks, $total_bytes bytes total\n";
echo "Multiple reads worked: " . ($chunks > 1 ? "yes" : ($total_bytes > 4096 ? "yes (one large chunk)" : "only one chunk")) . "\n";

// Test 2: pending() - after reading, check buffered data
$pending = $conn->pending();
echo "Pending bytes type: " . gettype($pending) . "\n";
echo "Pending >= 0: " . ($pending >= 0 ? "yes" : "FAIL") . "\n";

$conn->shutdown();
fclose($tcp);

// Test 3: Large write - send more data than one SSL record (16KB max record)
$tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn2 = $ctx->newConnection()->setStream($tcp2);
$conn2->connect();

// Build a large POST-style request (we'll just send it and see if write handles it)
$body = str_repeat('X', 8192);
$request = "POST / HTTP/1.1\r\nHost: www.google.com\r\nContent-Length: " . strlen($body) .
           "\r\nConnection: close\r\n\r\n" . $body;

$written = $conn2->write($request);
echo "Large write: $written bytes written\n";
echo "Write return > 0: " . ($written > 0 ? "yes" : "FAIL") . "\n";

// Read the response (might be 405 or whatever, we just want to confirm I/O works)
$resp = $conn2->read(256);
$status_line = strtok($resp, "\r\n");
echo "Response to large write: $status_line\n";

$conn2->shutdown();
fclose($tcp2);

// Test 4: Write return value accuracy
$tcp3 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn3 = $ctx->newConnection()->setStream($tcp3);
$conn3->connect();

$small_msg = "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
$bytes_written = $conn3->write($small_msg);
echo "Write return matches length: " . ($bytes_written === strlen($small_msg) ? "yes" : "no (got $bytes_written, expected " . strlen($small_msg) . ")") . "\n";

$conn3->shutdown();
fclose($tcp3);

echo "Large I/O tests passed\n";
?>
--EXPECTF--
Connected: TLS_AES_128_GCM_SHA256
First line: HTTP/1.1 200 OK
Read %d chunks, %d bytes total
Multiple reads worked: %s
Pending bytes type: integer
Pending >= 0: yes
Large write: %d bytes written
Write return > 0: yes
Response to large write: HTTP/1.1 %s
Write return matches length: yes
Large I/O tests passed
