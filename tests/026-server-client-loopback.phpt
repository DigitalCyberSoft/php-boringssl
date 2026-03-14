--TEST--
Server and client loopback - full TLS over socket pair
--EXTENSIONS--
boringssl
sockets
pcntl
openssl
--FILE--
<?php
// Generate a self-signed cert using PHP's openssl extension
$privkey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$csr = openssl_csr_new(['CN' => 'localhost'], $privkey);
$cert = openssl_csr_sign($csr, null, $privkey, 365);

$cert_file = tempnam(sys_get_temp_dir(), 'bssl_cert_');
$key_file = tempnam(sys_get_temp_dir(), 'bssl_key_');
openssl_x509_export_to_file($cert, $cert_file);
openssl_pkey_export_to_file($privkey, $key_file);

// Create a socket pair and export to streams
$pair = [];
if (!socket_create_pair(AF_UNIX, SOCK_STREAM, 0, $pair)) {
    echo "FAIL: socket_create_pair\n"; exit;
}
$server_stream = socket_export_stream($pair[0]);
$client_stream = socket_export_stream($pair[1]);

// Server context
$server_ctx = (new BoringSSL\Context())->newServer()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->useCertificateFile($cert_file)
    ->usePrivateKeyFile($key_file);

// Client context
$client_ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->setVerify(BoringSSL\VERIFY_NONE);

$pid = pcntl_fork();
if ($pid === -1) { echo "FAIL: fork\n"; exit; }

if ($pid === 0) {
    // Child = server
    fclose($client_stream);
    $server_conn = $server_ctx->newConnection()->setStream($server_stream);
    if (!$server_conn->accept()) { exit(1); }

    $data = $server_conn->read(1024);
    $server_conn->write(strtoupper($data));
    $server_conn->shutdown();
    fclose($server_stream);
    exit(0);
} else {
    // Parent = client
    fclose($server_stream);
    $client_conn = $client_ctx->newConnection()->setStream($client_stream);

    if (!$client_conn->connect()) { echo "FAIL: connect\n"; exit; }

    echo "Connected: " . $client_conn->getNegotiatedCipher() . "\n";
    echo "Protocol: 0x" . dechex($client_conn->getProtocolVersion()) . "\n";

    $msg = "hello from php boringssl";
    $client_conn->write($msg);
    $response = $client_conn->read(1024);

    echo "Sent: $msg\n";
    echo "Received: $response\n";
    echo "Echo correct: " . ($response === strtoupper($msg) ? "yes" : "FAIL") . "\n";

    // Shutdown may fail if the server already closed its side
    try { $client_conn->shutdown(); } catch (BoringSSL\Exception $e) { /* ok */ }
    fclose($client_stream);

    pcntl_waitpid($pid, $status);
    echo "Server exit: " . (pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0 ? "clean" : "error") . "\n";
}

unlink($cert_file);
unlink($key_file);

echo "Loopback test passed\n";
?>
--EXPECT--
Connected: TLS_AES_128_GCM_SHA256
Protocol: 0x304
Sent: hello from php boringssl
Received: HELLO FROM PHP BORINGSSL
Echo correct: yes
Server exit: clean
Loopback test passed
