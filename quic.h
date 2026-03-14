/*
  +----------------------------------------------------------------------+
  | BoringSSL extension for PHP - QUIC transport via ngtcp2              |
  +----------------------------------------------------------------------+
  | Licensed under the ISC license (OpenSSL-compatible).                 |
  | See: https://boringssl.googlesource.com/boringssl/+/HEAD/LICENSE     |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_BORINGSSL_QUIC_H
#define PHP_BORINGSSL_QUIC_H

#ifdef HAVE_BORINGSSL_QUIC

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>

/* Forward declarations */
struct _bssl_quic_conn_obj;
struct _bssl_quic_stream_entry;

/* Per-stream receive buffer */
typedef struct _bssl_quic_recv_buf {
    uint8_t *data;
    size_t len;
    size_t cap;
    size_t read_offset;
} bssl_quic_recv_buf;

/* Per-stream write buffer (for data not yet consumed by ngtcp2) */
typedef struct _bssl_quic_write_buf {
    uint8_t *data;
    size_t len;
    size_t cap;
    size_t sent_offset;
} bssl_quic_write_buf;

/* Internal stream tracking (owned by connection) */
typedef struct _bssl_quic_stream_entry {
    int64_t stream_id;
    int is_bidi;
    int fin_received;
    int fin_sent;
    int closed;
    bssl_quic_recv_buf recv;
    bssl_quic_write_buf send;
    struct _bssl_quic_stream_entry *next;
} bssl_quic_stream_entry;

/* BoringSSL\QuicConnection object */
typedef struct _bssl_quic_conn_obj {
    /* ngtcp2 conn_ref — must be accessible for SSL_set_app_data */
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_conn *conn;
    SSL_CTX *ssl_ctx;
    SSL *ssl;

    /* Network */
    int fd;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;

    /* Config */
    char *host;
    char *peer_name;
    int port;
    double timeout;
    zend_bool verify_peer;
    zend_bool connected;
    zend_bool closed;
    ngtcp2_ccerr last_error;

    /* Streams */
    bssl_quic_stream_entry *streams;
    uint32_t stream_count;

    zend_object std;
} bssl_quic_conn_obj;

/* BoringSSL\QuicStream object */
typedef struct _bssl_quic_stream_obj {
    bssl_quic_stream_entry *entry;
    zend_object *conn_zobj;
    zend_object std;
} bssl_quic_stream_obj;

/* Object conversion helpers */
static inline bssl_quic_conn_obj *bssl_quic_conn_from_obj(zend_object *obj) {
    return (bssl_quic_conn_obj *)((char *)obj - XtOffsetOf(bssl_quic_conn_obj, std));
}

static inline bssl_quic_stream_obj *bssl_quic_stream_from_obj(zend_object *obj) {
    return (bssl_quic_stream_obj *)((char *)obj - XtOffsetOf(bssl_quic_stream_obj, std));
}

#define Z_BSSL_QUIC_CONN_P(zv)   bssl_quic_conn_from_obj(Z_OBJ_P(zv))
#define Z_BSSL_QUIC_STREAM_P(zv) bssl_quic_stream_from_obj(Z_OBJ_P(zv))

/* Class entries */
extern zend_class_entry *bssl_quic_conn_ce;
extern zend_class_entry *bssl_quic_stream_ce;

/* Registration called from MINIT */
void bssl_quic_minit(int module_number);

/* Procedural functions (registered in bssl_quic_minit via zend_register_functions) */

/* Stream type constants */
#define BSSL_QUIC_STREAM_BIDI 0
#define BSSL_QUIC_STREAM_UNI  1

/* Write flag constants */
#define BSSL_QUIC_WRITE_FLAG_CONCLUDE 1

#endif /* HAVE_BORINGSSL_QUIC */
#endif /* PHP_BORINGSSL_QUIC_H */
