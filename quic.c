/*
  +----------------------------------------------------------------------+
  | BoringSSL extension for PHP - QUIC transport via ngtcp2              |
  +----------------------------------------------------------------------+
  | Licensed under the ISC license (OpenSSL-compatible).                 |
  | See: https://boringssl.googlesource.com/boringssl/+/HEAD/LICENSE     |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "php.h"
#include "ext/spl/spl_exceptions.h"
#include "zend_exceptions.h"
#include "zend_smart_str.h"
#include "php_boringssl.h"

#ifdef HAVE_BORINGSSL_QUIC

#include <errno.h>
#include <string.h>
#include <time.h>

/* Class entries */
zend_class_entry *bssl_quic_conn_ce;
zend_class_entry *bssl_quic_stream_ce;

static zend_object_handlers bssl_quic_conn_handlers;
static zend_object_handlers bssl_quic_stream_handlers;

/* --------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------ */

static uint64_t bssl_quic_timestamp(void) {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static int bssl_quic_resolve(const char *host, int port,
        struct sockaddr_storage *addr, socklen_t *addrlen) {
    struct addrinfo hints = {0}, *res;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;
    memcpy(addr, res->ai_addr, res->ai_addrlen);
    *addrlen = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

/* Buffer and stream limits */
#define BSSL_QUIC_MAX_BUFFER_SIZE (64 * 1024 * 1024)  /* 64 MiB per buffer */
#define BSSL_QUIC_MAX_STREAMS     1024                  /* max tracked streams */

/* Receive buffer helpers */
static int recv_buf_append(bssl_quic_recv_buf *buf,
        const uint8_t *data, size_t len) {
    size_t needed = buf->len + len;
    if (needed > BSSL_QUIC_MAX_BUFFER_SIZE) return -1;
    if (needed > buf->cap) {
        size_t newcap = buf->cap ? buf->cap * 2 : 4096;
        while (newcap < needed) newcap *= 2;
        if (newcap > BSSL_QUIC_MAX_BUFFER_SIZE) newcap = BSSL_QUIC_MAX_BUFFER_SIZE;
        buf->data = erealloc(buf->data, newcap);
        buf->cap = newcap;
    }
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return 0;
}

static bssl_quic_stream_entry *find_stream(bssl_quic_conn_obj *qc,
        int64_t stream_id) {
    bssl_quic_stream_entry *s = qc->streams;
    while (s) {
        if (s->stream_id == stream_id) return s;
        s = s->next;
    }
    return NULL;
}

static bssl_quic_stream_entry *find_or_create_stream(bssl_quic_conn_obj *qc,
        int64_t stream_id) {
    bssl_quic_stream_entry *s = find_stream(qc, stream_id);
    if (s) return s;
    s = ecalloc(1, sizeof(bssl_quic_stream_entry));
    s->stream_id = stream_id;
    s->is_bidi = !(stream_id & 0x02);
    s->next = qc->streams;
    qc->streams = s;
    qc->stream_count++;
    return s;
}

static void free_stream_entry(bssl_quic_stream_entry *s) {
    if (s->recv.data) efree(s->recv.data);
    if (s->send.data) efree(s->send.data);
    efree(s);
}

/* --------------------------------------------------------------------------
 * ngtcp2 callbacks
 * ------------------------------------------------------------------------ */

static ngtcp2_conn *bssl_quic_get_conn(ngtcp2_crypto_conn_ref *ref) {
    bssl_quic_conn_obj *qc = (bssl_quic_conn_obj *)ref->user_data;
    return qc->conn;
}

static void bssl_quic_rand_cb(uint8_t *dest, size_t destlen,
        const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    RAND_bytes(dest, (int)destlen);
}

static int bssl_quic_get_new_connection_id_cb(ngtcp2_conn *conn,
        ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data) {
    (void)conn; (void)user_data;
    if (RAND_bytes(cid->data, (int)cidlen) != 1) return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cidlen;
    if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static int bssl_quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
        int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen,
        void *user_data, void *stream_user_data) {
    (void)conn; (void)offset; (void)stream_user_data;
    bssl_quic_conn_obj *qc = user_data;
    if (qc->stream_count >= BSSL_QUIC_MAX_STREAMS && !find_stream(qc, stream_id)) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    bssl_quic_stream_entry *s = find_or_create_stream(qc, stream_id);
    if (datalen > 0) {
        if (recv_buf_append(&s->recv, data, datalen) != 0) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }
    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
        s->fin_received = 1;
    }
    return 0;
}

static int bssl_quic_stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
        int64_t stream_id, uint64_t app_error_code, void *user_data,
        void *stream_user_data) {
    (void)conn; (void)flags; (void)app_error_code; (void)stream_user_data;
    bssl_quic_conn_obj *qc = user_data;
    bssl_quic_stream_entry *s = find_stream(qc, stream_id);
    if (s) s->closed = 1;
    return 0;
}

static int bssl_quic_extend_max_local_streams_bidi_cb(ngtcp2_conn *conn,
        uint64_t max_streams, void *user_data) {
    (void)conn; (void)max_streams; (void)user_data;
    return 0;
}

static int bssl_quic_extend_max_local_streams_uni_cb(ngtcp2_conn *conn,
        uint64_t max_streams, void *user_data) {
    (void)conn; (void)max_streams; (void)user_data;
    return 0;
}

static int bssl_quic_acked_stream_data_offset_cb(ngtcp2_conn *conn,
        int64_t stream_id, uint64_t offset, uint64_t datalen,
        void *user_data, void *stream_user_data) {
    (void)conn; (void)stream_id; (void)offset; (void)datalen;
    (void)user_data; (void)stream_user_data;
    return 0;
}

/* --------------------------------------------------------------------------
 * UDP I/O
 * ------------------------------------------------------------------------ */

static int bssl_quic_send_packet(bssl_quic_conn_obj *qc,
        const uint8_t *data, size_t datalen) {
    struct iovec iov = { .iov_base = (void *)data, .iov_len = datalen };
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    ssize_t nwrite;
    do { nwrite = sendmsg(qc->fd, &msg, 0); }
    while (nwrite == -1 && errno == EINTR);
    if (nwrite > 0) qc->conn_ref.user_data = qc; /* keep alive */
    return nwrite >= 0 ? 0 : -1;
}

static int bssl_quic_drain_packets(bssl_quic_conn_obj *qc) {
    uint8_t buf[65536];
    struct sockaddr_storage addr;
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct msghdr msg = {0};
    msg.msg_name = &addr;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    for (;;) {
        msg.msg_namelen = sizeof(addr);
        ssize_t nread = recvmsg(qc->fd, &msg, MSG_DONTWAIT);
        if (nread == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            return -1;
        }
        ngtcp2_path path;
        path.local.addrlen = qc->local_addrlen;
        path.local.addr = (struct sockaddr *)&qc->local_addr;
        path.remote.addrlen = msg.msg_namelen;
        path.remote.addr = msg.msg_name;
        ngtcp2_pkt_info pi = {0};
        int rv = ngtcp2_conn_read_pkt(qc->conn, &path, &pi, buf,
                (size_t)nread, bssl_quic_timestamp());
        if (rv != 0) {
            if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_DROP_CONN) break;
            if (!qc->last_error.error_code) {
                if (rv == NGTCP2_ERR_CRYPTO)
                    ngtcp2_ccerr_set_tls_alert(&qc->last_error,
                        ngtcp2_conn_get_tls_alert(qc->conn), NULL, 0);
                else
                    ngtcp2_ccerr_set_liberr(&qc->last_error, rv, NULL, 0);
            }
            return -1;
        }
    }
    return 0;
}

static int bssl_quic_write_streams(bssl_quic_conn_obj *qc) {
    uint8_t buf[1452];
    ngtcp2_tstamp ts = bssl_quic_timestamp();
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;

    ngtcp2_path_storage_zero(&ps);

    /* Try to write stream data for streams with pending sends */
    bssl_quic_stream_entry *s = qc->streams;
    while (s) {
        if (!s->closed && s->send.len > s->send.sent_offset) {
            size_t remaining = s->send.len - s->send.sent_offset;
            ngtcp2_vec datav = {
                .base = s->send.data + s->send.sent_offset,
                .len = remaining
            };
            uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
            if (s->fin_sent) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            ngtcp2_ssize wdatalen;

            for (;;) {
                ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(qc->conn,
                    &ps.path, &pi, buf, sizeof(buf), &wdatalen, flags,
                    s->stream_id, &datav, 1, ts);
                if (nwrite < 0) {
                    if (nwrite == NGTCP2_ERR_WRITE_MORE) {
                        s->send.sent_offset += (size_t)wdatalen;
                        datav.base = s->send.data + s->send.sent_offset;
                        datav.len = s->send.len - s->send.sent_offset;
                        if (datav.len == 0) break;
                        continue;
                    }
                    return (int)nwrite;
                }
                if (wdatalen > 0) s->send.sent_offset += (size_t)wdatalen;
                if (nwrite > 0) bssl_quic_send_packet(qc, buf, (size_t)nwrite);
                break;
            }
        } else if (!s->closed && s->fin_sent && s->send.sent_offset >= s->send.len) {
            /* Send FIN with no data */
            ngtcp2_ssize wdatalen;
            ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(qc->conn,
                &ps.path, &pi, buf, sizeof(buf), &wdatalen,
                NGTCP2_WRITE_STREAM_FLAG_FIN, s->stream_id, NULL, 0, ts);
            if (nwrite > 0) bssl_quic_send_packet(qc, buf, (size_t)nwrite);
            if (nwrite >= 0) s->fin_sent = 2; /* mark as actually sent */
        }
        s = s->next;
    }

    /* Also write any control packets (ACKs, handshake, etc.) */
    for (;;) {
        ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(qc->conn,
            &ps.path, &pi, buf, sizeof(buf), ts);
        if (nwrite < 0) return (int)nwrite;
        if (nwrite == 0) break;
        bssl_quic_send_packet(qc, buf, (size_t)nwrite);
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * Core event loop — runs until predicate is satisfied or timeout
 * ------------------------------------------------------------------------ */

typedef int (*bssl_quic_predicate)(bssl_quic_conn_obj *qc, void *ctx);

static int bssl_quic_process(bssl_quic_conn_obj *qc, double timeout_secs,
        bssl_quic_predicate pred, void *pred_ctx) {
    uint64_t deadline = bssl_quic_timestamp() +
        (uint64_t)(timeout_secs * NGTCP2_SECONDS);

    struct pollfd pfd = { .fd = qc->fd, .events = POLLIN };

    for (;;) {
        /* Check predicate first */
        if (pred && pred(qc, pred_ctx)) return 0;

        /* Check deadline */
        uint64_t now = bssl_quic_timestamp();
        if (now >= deadline) return -1; /* timeout */

        /* Calculate poll timeout */
        uint64_t expiry = ngtcp2_conn_get_expiry(qc->conn);
        uint64_t wait_ns = deadline - now;
        if (expiry != UINT64_MAX && expiry > now) {
            uint64_t exp_ns = expiry - now;
            if (exp_ns < wait_ns) wait_ns = exp_ns;
        } else if (expiry != UINT64_MAX && expiry <= now) {
            wait_ns = 0;
        }
        uint64_t poll_ms_u64 = wait_ns / 1000000;
        int poll_ms = (poll_ms_u64 > INT_MAX) ? INT_MAX : (int)poll_ms_u64;
        if (poll_ms < 1 && wait_ns > 0) poll_ms = 1;

        int ret = poll(&pfd, 1, poll_ms);
        (void)ret;

        now = bssl_quic_timestamp();

        /* Read incoming packets */
        if (pfd.revents & POLLIN) {
            if (bssl_quic_drain_packets(qc) != 0) return -2;
        }

        /* Handle timer expiry */
        if (expiry != UINT64_MAX && now >= expiry) {
            int rv = ngtcp2_conn_handle_expiry(qc->conn, now);
            if (rv != 0) return -2;
        }

        /* Write outgoing packets (ACKs, handshake, stream data) */
        if (bssl_quic_write_streams(qc) < 0) {
            /* Ignore non-fatal errors during writes */
        }

        /* Check for connection closure */
        if (ngtcp2_conn_in_closing_period(qc->conn) ||
            ngtcp2_conn_in_draining_period(qc->conn)) {
            return -2;
        }
    }
}

/* Predicates */
static int pred_handshake_done(bssl_quic_conn_obj *qc, void *ctx) {
    (void)ctx;
    return ngtcp2_conn_get_handshake_completed(qc->conn);
}

static int pred_stream_has_data(bssl_quic_conn_obj *qc, void *ctx) {
    int64_t stream_id = *(int64_t *)ctx;
    bssl_quic_stream_entry *s = find_stream(qc, stream_id);
    if (!s) return 0;
    return (s->recv.len > s->recv.read_offset) || s->fin_received || s->closed;
}

/* --------------------------------------------------------------------------
 * QuicConnection PHP object handlers
 * ------------------------------------------------------------------------ */

static zend_object *bssl_quic_conn_create(zend_class_entry *ce) {
    bssl_quic_conn_obj *obj = zend_object_alloc(sizeof(bssl_quic_conn_obj), ce);
    zend_object_std_init(&obj->std, ce);
    object_properties_init(&obj->std, ce);
    obj->std.handlers = &bssl_quic_conn_handlers;
    obj->fd = -1;
    obj->conn = NULL;
    obj->ssl = NULL;
    obj->ssl_ctx = NULL;
    obj->host = NULL;
    obj->peer_name = NULL;
    obj->timeout = 10.0;
    obj->verify_peer = 1;
    obj->connected = 0;
    obj->closed = 0;
    obj->streams = NULL;
    obj->stream_count = 0;
    ngtcp2_ccerr_default(&obj->last_error);
    return &obj->std;
}

static void bssl_quic_conn_free(zend_object *object) {
    bssl_quic_conn_obj *qc = bssl_quic_conn_from_obj(object);

    /* Send CONNECTION_CLOSE if still connected */
    if (qc->conn && !qc->closed &&
        !ngtcp2_conn_in_closing_period(qc->conn) &&
        !ngtcp2_conn_in_draining_period(qc->conn)) {
        uint8_t buf[1280];
        ngtcp2_path_storage ps;
        ngtcp2_pkt_info pi;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
            qc->conn, &ps.path, &pi, buf, sizeof(buf),
            &qc->last_error, bssl_quic_timestamp());
        if (nwrite > 0 && qc->fd >= 0) {
            bssl_quic_send_packet(qc, buf, (size_t)nwrite);
        }
    }

    /* Free streams */
    bssl_quic_stream_entry *s = qc->streams;
    while (s) {
        bssl_quic_stream_entry *next = s->next;
        free_stream_entry(s);
        s = next;
    }
    qc->streams = NULL;

    if (qc->conn) { ngtcp2_conn_del(qc->conn); qc->conn = NULL; }
    if (qc->ssl) { SSL_free(qc->ssl); qc->ssl = NULL; }
    if (qc->ssl_ctx) { SSL_CTX_free(qc->ssl_ctx); qc->ssl_ctx = NULL; }
    if (qc->fd >= 0) { close(qc->fd); qc->fd = -1; }
    if (qc->host) { efree(qc->host); qc->host = NULL; }
    if (qc->peer_name) { efree(qc->peer_name); qc->peer_name = NULL; }

    zend_object_std_dtor(&qc->std);
}

/* --------------------------------------------------------------------------
 * QuicStream PHP object handlers
 * ------------------------------------------------------------------------ */

static zend_object *bssl_quic_stream_create(zend_class_entry *ce) {
    bssl_quic_stream_obj *obj = zend_object_alloc(sizeof(bssl_quic_stream_obj), ce);
    zend_object_std_init(&obj->std, ce);
    object_properties_init(&obj->std, ce);
    obj->std.handlers = &bssl_quic_stream_handlers;
    obj->entry = NULL;
    obj->conn_zobj = NULL;
    return &obj->std;
}

static void bssl_quic_stream_free(zend_object *object) {
    bssl_quic_stream_obj *sobj = bssl_quic_stream_from_obj(object);
    if (sobj->conn_zobj) {
        OBJ_RELEASE(sobj->conn_zobj);
        sobj->conn_zobj = NULL;
    }
    zend_object_std_dtor(&sobj->std);
}

/* --------------------------------------------------------------------------
 * QuicConnection methods
 * ------------------------------------------------------------------------ */

PHP_METHOD(QuicConnection, __construct) {
    char *host; size_t host_len;
    zend_long port;
    zval *options = NULL;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(host, host_len)
        Z_PARAM_LONG(port)
        Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY(options)
    ZEND_PARSE_PARAMETERS_END();

    if (port < 1 || port > 65535) {
        zend_throw_exception(zend_ce_value_error,
            "Port must be between 1 and 65535", 0);
        RETURN_THROWS();
    }

    bssl_quic_conn_obj *qc = Z_BSSL_QUIC_CONN_P(ZEND_THIS);
    qc->host = estrndup(host, host_len);
    qc->port = (int)port;

    if (options) {
        zval *opt;

        opt = zend_hash_str_find(Z_ARRVAL_P(options), "peer_name", sizeof("peer_name") - 1);
        if (opt && Z_TYPE_P(opt) == IS_STRING)
            qc->peer_name = estrndup(Z_STRVAL_P(opt), Z_STRLEN_P(opt));

        opt = zend_hash_str_find(Z_ARRVAL_P(options), "verify_peer", sizeof("verify_peer") - 1);
        if (opt) qc->verify_peer = zend_is_true(opt);

        opt = zend_hash_str_find(Z_ARRVAL_P(options), "timeout", sizeof("timeout") - 1);
        if (opt) {
            qc->timeout = zval_get_double(opt);
            if (qc->timeout <= 0) qc->timeout = 10.0;
        }
    }

    /* --- SSL context --- */
    qc->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!qc->ssl_ctx) {
        bssl_throw_ssl_error("Failed to create QUIC SSL context");
        RETURN_THROWS();
    }

    if (ngtcp2_crypto_boringssl_configure_client_context(qc->ssl_ctx) != 0) {
        bssl_throw_ssl_error("Failed to configure BoringSSL for QUIC");
        RETURN_THROWS();
    }

    /* ALPN */
    if (options) {
        zval *alpn = zend_hash_str_find(Z_ARRVAL_P(options), "alpn", sizeof("alpn") - 1);
        if (alpn && Z_TYPE_P(alpn) == IS_ARRAY) {
            smart_str alpn_buf = {0};
            zval *entry;
            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(alpn), entry) {
                zend_string *proto = zval_get_string(entry);
                if (ZSTR_LEN(proto) == 0 || ZSTR_LEN(proto) > 255) {
                    smart_str_free(&alpn_buf);
                    zend_string_release(proto);
                    zend_throw_exception(zend_ce_value_error,
                        "ALPN protocol name must be 1-255 bytes", 0);
                    RETURN_THROWS();
                }
                smart_str_appendc(&alpn_buf, (char)ZSTR_LEN(proto));
                smart_str_append(&alpn_buf, proto);
                zend_string_release(proto);
            } ZEND_HASH_FOREACH_END();
            if (alpn_buf.s) {
                SSL_CTX_set_alpn_protos(qc->ssl_ctx,
                    (const uint8_t *)ZSTR_VAL(alpn_buf.s), ZSTR_LEN(alpn_buf.s));
                smart_str_free(&alpn_buf);
            }
        }
    }

    /* Verification */
    if (qc->verify_peer) {
        SSL_CTX_set_verify(qc->ssl_ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_default_verify_paths(qc->ssl_ctx);
    } else {
        SSL_CTX_set_verify(qc->ssl_ctx, SSL_VERIFY_NONE, NULL);
    }

    /* Cipher suites */
    if (options) {
        zval *cs = zend_hash_str_find(Z_ARRVAL_P(options), "ciphersuites", sizeof("ciphersuites") - 1);
        if (cs && Z_TYPE_P(cs) == IS_STRING) {
            if (SSL_CTX_set_cipher_list(qc->ssl_ctx, Z_STRVAL_P(cs)) != 1) {
                bssl_throw_ssl_error("Failed to set QUIC cipher list");
                RETURN_THROWS();
            }
        }
    }

    /* BoringSSL TLS fingerprint features */
    SSL_CTX_set_grease_enabled(qc->ssl_ctx, 1);
    SSL_CTX_set_permute_extensions(qc->ssl_ctx, 1);

    /* --- SSL object --- */
    qc->ssl = SSL_new(qc->ssl_ctx);
    if (!qc->ssl) {
        bssl_throw_ssl_error("Failed to create QUIC SSL object");
        RETURN_THROWS();
    }

    SSL_set_connect_state(qc->ssl);
    const char *sni = qc->peer_name ? qc->peer_name : qc->host;
    SSL_set_tlsext_host_name(qc->ssl, sni);

    /* Enforce certificate hostname verification */
    if (qc->verify_peer) {
        X509_VERIFY_PARAM *param = SSL_get0_param(qc->ssl);
        X509_VERIFY_PARAM_set1_host(param, sni, strlen(sni));
    }

    /* conn_ref for ngtcp2 crypto callbacks */
    qc->conn_ref.get_conn = bssl_quic_get_conn;
    qc->conn_ref.user_data = qc;
    SSL_set_app_data(qc->ssl, &qc->conn_ref);
}

PHP_METHOD(QuicConnection, connect) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_quic_conn_obj *qc = Z_BSSL_QUIC_CONN_P(ZEND_THIS);

    if (qc->connected) {
        zend_throw_exception(spl_ce_RuntimeException, "Already connected", 0);
        RETURN_THROWS();
    }
    if (!qc->ssl_ctx) {
        zend_throw_exception(spl_ce_RuntimeException,
            "QUIC context not initialized", 0);
        RETURN_THROWS();
    }

    /* Resolve and create UDP socket */
    if (bssl_quic_resolve(qc->host, qc->port,
            &qc->remote_addr, &qc->remote_addrlen) != 0) {
        zend_throw_exception_ex(spl_ce_RuntimeException, 0,
            "Failed to resolve host: %s", qc->host);
        RETURN_THROWS();
    }

    qc->fd = socket(qc->remote_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (qc->fd < 0) {
        zend_throw_exception_ex(spl_ce_RuntimeException, 0,
            "Failed to create UDP socket: %s", strerror(errno));
        RETURN_THROWS();
    }

    if (connect(qc->fd, (struct sockaddr *)&qc->remote_addr,
            qc->remote_addrlen) != 0) {
        close(qc->fd); qc->fd = -1;
        zend_throw_exception_ex(spl_ce_RuntimeException, 0,
            "UDP connect failed: %s", strerror(errno));
        RETURN_THROWS();
    }

    qc->local_addrlen = sizeof(qc->local_addr);
    if (getsockname(qc->fd, (struct sockaddr *)&qc->local_addr,
            &qc->local_addrlen) != 0) {
        close(qc->fd); qc->fd = -1;
        zend_throw_exception_ex(spl_ce_RuntimeException, 0,
            "getsockname failed: %s", strerror(errno));
        RETURN_THROWS();
    }

    /* Set non-blocking for poll-based event loop */
    int fl = fcntl(qc->fd, F_GETFL);
    if (fl == -1 || fcntl(qc->fd, F_SETFL, fl | O_NONBLOCK) == -1) {
        close(qc->fd); qc->fd = -1;
        zend_throw_exception_ex(spl_ce_RuntimeException, 0,
            "Failed to set non-blocking mode: %s", strerror(errno));
        RETURN_THROWS();
    }

    /* --- ngtcp2 connection --- */
    ngtcp2_callbacks callbacks = {
        .client_initial = ngtcp2_crypto_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_retry = ngtcp2_crypto_recv_retry_cb,
        .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
        .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
        .rand = bssl_quic_rand_cb,
        .get_new_connection_id = bssl_quic_get_new_connection_id_cb,
        .recv_stream_data = bssl_quic_recv_stream_data_cb,
        .stream_close = bssl_quic_stream_close_cb,
        .extend_max_local_streams_bidi = bssl_quic_extend_max_local_streams_bidi_cb,
        .extend_max_local_streams_uni = bssl_quic_extend_max_local_streams_uni_cb,
        .acked_stream_data_offset = bssl_quic_acked_stream_data_offset_cb,
    };

    ngtcp2_cid dcid, scid;
    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    RAND_bytes(dcid.data, (int)dcid.datalen);
    scid.datalen = 8;
    RAND_bytes(scid.data, (int)scid.datalen);

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = bssl_quic_timestamp();

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni = 3;
    params.initial_max_streams_bidi = 100;
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.max_idle_timeout = (uint64_t)(qc->timeout * 2) * NGTCP2_SECONDS;

    ngtcp2_path path = {
        .local = { .addr = (struct sockaddr *)&qc->local_addr,
                    .addrlen = qc->local_addrlen },
        .remote = { .addr = (struct sockaddr *)&qc->remote_addr,
                     .addrlen = qc->remote_addrlen },
    };

    int rv = ngtcp2_conn_client_new(&qc->conn, &dcid, &scid, &path,
        NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, NULL, qc);
    if (rv != 0) {
        zend_throw_exception_ex(spl_ce_RuntimeException, 0,
            "ngtcp2_conn_client_new failed: %s", ngtcp2_strerror(rv));
        RETURN_THROWS();
    }

    ngtcp2_conn_set_tls_native_handle(qc->conn, qc->ssl);

    /* Drive the handshake via the event loop */
    /* First, write initial packets */
    bssl_quic_write_streams(qc);

    rv = bssl_quic_process(qc, qc->timeout, pred_handshake_done, NULL);
    if (rv != 0) {
        const char *msg = rv == -1 ? "QUIC handshake timed out" :
                                     "QUIC handshake failed";
        zend_throw_exception(spl_ce_RuntimeException, msg, 0);
        RETURN_THROWS();
    }

    qc->connected = 1;
    RETURN_TRUE;
}

PHP_METHOD(QuicConnection, isConnected) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_quic_conn_obj *qc = Z_BSSL_QUIC_CONN_P(ZEND_THIS);
    RETURN_BOOL(qc->connected && !qc->closed &&
        qc->conn && !ngtcp2_conn_in_closing_period(qc->conn) &&
        !ngtcp2_conn_in_draining_period(qc->conn));
}

PHP_METHOD(QuicConnection, openStream) {
    zend_long type = BSSL_QUIC_STREAM_BIDI;
    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(type)
    ZEND_PARSE_PARAMETERS_END();

    bssl_quic_conn_obj *qc = Z_BSSL_QUIC_CONN_P(ZEND_THIS);
    if (!qc->connected || !qc->conn) {
        zend_throw_exception(spl_ce_RuntimeException,
            "Not connected", 0);
        RETURN_THROWS();
    }

    int64_t stream_id;
    int rv;
    if (type == BSSL_QUIC_STREAM_UNI) {
        rv = ngtcp2_conn_open_uni_stream(qc->conn, &stream_id, NULL);
    } else {
        rv = ngtcp2_conn_open_bidi_stream(qc->conn, &stream_id, NULL);
    }

    if (rv != 0) {
        zend_throw_exception_ex(spl_ce_RuntimeException, 0,
            "Failed to open stream: %s", ngtcp2_strerror(rv));
        RETURN_THROWS();
    }

    bssl_quic_stream_entry *entry = find_or_create_stream(qc, stream_id);

    object_init_ex(return_value, bssl_quic_stream_ce);
    bssl_quic_stream_obj *sobj = Z_BSSL_QUIC_STREAM_P(return_value);
    sobj->entry = entry;
    sobj->conn_zobj = Z_OBJ_P(ZEND_THIS);
    GC_ADDREF(sobj->conn_zobj);
}

PHP_METHOD(QuicConnection, close) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_quic_conn_obj *qc = Z_BSSL_QUIC_CONN_P(ZEND_THIS);
    if (qc->closed) RETURN_TRUE;

    if (qc->conn && !ngtcp2_conn_in_closing_period(qc->conn) &&
        !ngtcp2_conn_in_draining_period(qc->conn)) {
        uint8_t buf[1280];
        ngtcp2_path_storage ps;
        ngtcp2_pkt_info pi;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
            qc->conn, &ps.path, &pi, buf, sizeof(buf),
            &qc->last_error, bssl_quic_timestamp());
        if (nwrite > 0 && qc->fd >= 0)
            bssl_quic_send_packet(qc, buf, (size_t)nwrite);
    }

    qc->closed = 1;
    qc->connected = 0;
    RETURN_TRUE;
}

PHP_METHOD(QuicConnection, getAlpn) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_quic_conn_obj *qc = Z_BSSL_QUIC_CONN_P(ZEND_THIS);
    if (!qc->ssl) RETURN_EMPTY_STRING();
    const uint8_t *proto; unsigned proto_len;
    SSL_get0_alpn_selected(qc->ssl, &proto, &proto_len);
    if (proto && proto_len > 0) RETURN_STRINGL((const char *)proto, proto_len);
    RETURN_EMPTY_STRING();
}

/* --------------------------------------------------------------------------
 * QuicStream methods
 * ------------------------------------------------------------------------ */

#define BSSL_QSTREAM_CHECK(sobj) \
    do { \
        if (!(sobj)->entry || !(sobj)->conn_zobj) { \
            zend_throw_exception(spl_ce_RuntimeException, \
                "Stream not initialized", 0); \
            RETURN_THROWS(); \
        } \
    } while (0)

PHP_METHOD(QuicStream, write) {
    char *data; size_t data_len;
    zend_long flags = 0;
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(data, data_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END();

    bssl_quic_stream_obj *sobj = Z_BSSL_QUIC_STREAM_P(ZEND_THIS);
    BSSL_QSTREAM_CHECK(sobj);
    bssl_quic_conn_obj *qc = bssl_quic_conn_from_obj(sobj->conn_zobj);
    bssl_quic_stream_entry *s = sobj->entry;

    /* Append to write buffer */
    bssl_quic_write_buf *wb = &s->send;
    size_t needed = wb->len + data_len;
    if (needed > BSSL_QUIC_MAX_BUFFER_SIZE) {
        zend_throw_exception(spl_ce_RuntimeException,
            "QUIC stream write buffer limit exceeded", 0);
        RETURN_THROWS();
    }
    if (needed > wb->cap) {
        size_t newcap = wb->cap ? wb->cap * 2 : 4096;
        while (newcap < needed) newcap *= 2;
        if (newcap > BSSL_QUIC_MAX_BUFFER_SIZE) newcap = BSSL_QUIC_MAX_BUFFER_SIZE;
        wb->data = erealloc(wb->data, newcap);
        wb->cap = newcap;
    }
    memcpy(wb->data + wb->len, data, data_len);
    wb->len += data_len;

    if (flags & BSSL_QUIC_WRITE_FLAG_CONCLUDE) {
        s->fin_sent = 1;
    }

    /* Try to flush immediately */
    bssl_quic_write_streams(qc);

    RETURN_LONG((zend_long)data_len);
}

PHP_METHOD(QuicStream, read) {
    zend_long length = 0, timeout_ms = 0;
    ZEND_PARSE_PARAMETERS_START(0, 2)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(length)
        Z_PARAM_LONG(timeout_ms)
    ZEND_PARSE_PARAMETERS_END();

    bssl_quic_stream_obj *sobj = Z_BSSL_QUIC_STREAM_P(ZEND_THIS);
    BSSL_QSTREAM_CHECK(sobj);
    bssl_quic_conn_obj *qc = bssl_quic_conn_from_obj(sobj->conn_zobj);
    bssl_quic_stream_entry *s = sobj->entry;

    /* If no data buffered, run event loop to get some */
    if (s->recv.len <= s->recv.read_offset && !s->fin_received && !s->closed) {
        double timeout = timeout_ms > 0 ? (double)timeout_ms / 1000.0 : qc->timeout;
        int64_t sid = s->stream_id;
        bssl_quic_process(qc, timeout, pred_stream_has_data, &sid);
    }

    /* Check for FIN / closed with no data */
    size_t avail = s->recv.len - s->recv.read_offset;
    if (avail == 0) {
        if (s->fin_received || s->closed) {
            RETURN_NULL(); /* stream ended */
        }
        RETURN_FALSE; /* timeout, no data */
    }

    /* Return available data */
    size_t to_read = avail;
    if (length > 0 && (size_t)length < to_read) to_read = (size_t)length;

    zend_string *result = zend_string_init(
        (char *)s->recv.data + s->recv.read_offset, to_read, 0);
    s->recv.read_offset += to_read;

    /* Flow control: tell ngtcp2 we consumed data */
    ngtcp2_conn_extend_max_stream_offset(qc->conn, s->stream_id, to_read);
    ngtcp2_conn_extend_max_offset(qc->conn, to_read);

    RETURN_NEW_STR(result);
}

PHP_METHOD(QuicStream, conclude) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_quic_stream_obj *sobj = Z_BSSL_QUIC_STREAM_P(ZEND_THIS);
    BSSL_QSTREAM_CHECK(sobj);
    bssl_quic_conn_obj *qc = bssl_quic_conn_from_obj(sobj->conn_zobj);
    bssl_quic_stream_entry *s = sobj->entry;

    s->fin_sent = 1;
    bssl_quic_write_streams(qc);
    RETURN_TRUE;
}

PHP_METHOD(QuicStream, getId) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_quic_stream_obj *sobj = Z_BSSL_QUIC_STREAM_P(ZEND_THIS);
    BSSL_QSTREAM_CHECK(sobj);
    RETURN_LONG(sobj->entry->stream_id);
}

PHP_METHOD(QuicStream, getType) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_quic_stream_obj *sobj = Z_BSSL_QUIC_STREAM_P(ZEND_THIS);
    BSSL_QSTREAM_CHECK(sobj);
    RETURN_LONG(sobj->entry->is_bidi ? BSSL_QUIC_STREAM_BIDI : BSSL_QUIC_STREAM_UNI);
}

PHP_METHOD(QuicStream, isReadable) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_quic_stream_obj *sobj = Z_BSSL_QUIC_STREAM_P(ZEND_THIS);
    BSSL_QSTREAM_CHECK(sobj);
    RETURN_BOOL(!sobj->entry->closed && !sobj->entry->fin_received);
}

PHP_METHOD(QuicStream, isWritable) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_quic_stream_obj *sobj = Z_BSSL_QUIC_STREAM_P(ZEND_THIS);
    BSSL_QSTREAM_CHECK(sobj);
    RETURN_BOOL(!sobj->entry->closed && !sobj->entry->fin_sent);
}

/* --------------------------------------------------------------------------
 * Procedural functions
 * ------------------------------------------------------------------------ */

PHP_FUNCTION(boringssl_quic_connect) {
    char *host; size_t host_len;
    zend_long port;
    zval *options = NULL;

    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(host, host_len)
        Z_PARAM_LONG(port)
        Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY(options)
    ZEND_PARSE_PARAMETERS_END();

    /* Create QuicConnection object */
    object_init_ex(return_value, bssl_quic_conn_ce);

    /* Call __construct */
    zval args[3];
    ZVAL_STRINGL(&args[0], host, host_len);
    ZVAL_LONG(&args[1], port);
    int argc = 2;
    if (options) { ZVAL_COPY_VALUE(&args[2], options); argc = 3; }

    zval fn, rv;
    ZVAL_STRING(&fn, "__construct");
    call_user_function(NULL, return_value, &fn, &rv, argc, args);
    zval_ptr_dtor(&fn);
    zval_ptr_dtor(&args[0]);
    zval_ptr_dtor(&rv);

    if (EG(exception)) return;

    /* Call connect */
    ZVAL_STRING(&fn, "connect");
    call_user_function(NULL, return_value, &fn, &rv, 0, NULL);
    zval_ptr_dtor(&fn);
    zval_ptr_dtor(&rv);
}

PHP_FUNCTION(boringssl_quic_open_stream) {
    zval *conn_zv;
    zend_long type = BSSL_QUIC_STREAM_BIDI;
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_quic_conn_ce)
        Z_PARAM_OPTIONAL Z_PARAM_LONG(type)
    ZEND_PARSE_PARAMETERS_END();
    zval args[1]; ZVAL_LONG(&args[0], type);
    zval fn; ZVAL_STRING(&fn, "openStream");
    call_user_function(NULL, conn_zv, &fn, return_value, 1, args);
    zval_ptr_dtor(&fn);
}

PHP_FUNCTION(boringssl_quic_stream_write) {
    zval *stream_zv; char *data; size_t data_len; zend_long flags = 0;
    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_OBJECT_OF_CLASS(stream_zv, bssl_quic_stream_ce)
        Z_PARAM_STRING(data, data_len)
        Z_PARAM_OPTIONAL Z_PARAM_LONG(flags)
    ZEND_PARSE_PARAMETERS_END();
    bssl_quic_stream_obj *sobj = Z_BSSL_QUIC_STREAM_P(stream_zv);
    BSSL_QSTREAM_CHECK(sobj);
    bssl_quic_conn_obj *qc = bssl_quic_conn_from_obj(sobj->conn_zobj);
    bssl_quic_stream_entry *s = sobj->entry;
    bssl_quic_write_buf *wb = &s->send;
    size_t needed = wb->len + data_len;
    if (needed > BSSL_QUIC_MAX_BUFFER_SIZE) {
        zend_throw_exception(spl_ce_RuntimeException,
            "QUIC stream write buffer limit exceeded", 0);
        RETURN_THROWS();
    }
    if (needed > wb->cap) {
        size_t nc = wb->cap ? wb->cap * 2 : 4096;
        while (nc < needed) nc *= 2;
        if (nc > BSSL_QUIC_MAX_BUFFER_SIZE) nc = BSSL_QUIC_MAX_BUFFER_SIZE;
        wb->data = erealloc(wb->data, nc);
        wb->cap = nc;
    }
    memcpy(wb->data + wb->len, data, data_len);
    wb->len += data_len;
    if (flags & BSSL_QUIC_WRITE_FLAG_CONCLUDE) s->fin_sent = 1;
    bssl_quic_write_streams(qc);
    RETURN_LONG((zend_long)data_len);
}

PHP_FUNCTION(boringssl_quic_stream_read) {
    zval *stream_zv; zend_long length = 0, timeout_ms = 0;
    ZEND_PARSE_PARAMETERS_START(1, 3)
        Z_PARAM_OBJECT_OF_CLASS(stream_zv, bssl_quic_stream_ce)
        Z_PARAM_OPTIONAL Z_PARAM_LONG(length) Z_PARAM_LONG(timeout_ms)
    ZEND_PARSE_PARAMETERS_END();
    zval args[2]; ZVAL_LONG(&args[0], length); ZVAL_LONG(&args[1], timeout_ms);
    zval fn; ZVAL_STRING(&fn, "read");
    call_user_function(NULL, stream_zv, &fn, return_value, 2, args);
    zval_ptr_dtor(&fn);
}

PHP_FUNCTION(boringssl_quic_stream_conclude) {
    zval *stream_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(stream_zv, bssl_quic_stream_ce)
    ZEND_PARSE_PARAMETERS_END();
    zval fn, rv; ZVAL_STRING(&fn, "conclude");
    call_user_function(NULL, stream_zv, &fn, &rv, 0, NULL);
    zval_ptr_dtor(&fn);
    RETURN_ZVAL(&rv, 0, 0);
}

PHP_FUNCTION(boringssl_quic_close) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_quic_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    zval fn, rv; ZVAL_STRING(&fn, "close");
    call_user_function(NULL, conn_zv, &fn, &rv, 0, NULL);
    zval_ptr_dtor(&fn);
    RETURN_ZVAL(&rv, 0, 0);
}

PHP_FUNCTION(boringssl_quic_is_connected) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_quic_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_quic_conn_obj *qc = Z_BSSL_QUIC_CONN_P(conn_zv);
    RETURN_BOOL(qc->connected && !qc->closed &&
        qc->conn && !ngtcp2_conn_in_closing_period(qc->conn));
}

/* --------------------------------------------------------------------------
 * Arginfo
 * ------------------------------------------------------------------------ */

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_conn_construct, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_open_stream, 0, 0, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, type, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_stream_write, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_stream_read, 0, 0, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, length, IS_LONG, 0, "0")
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

/* Procedural arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_quic_connect, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_quic_conn, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\QuicConnection, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_quic_open_stream, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\QuicConnection, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, type, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_quic_stream_write, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, stream, BoringSSL\\QuicStream, 0)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_quic_stream_read, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, stream, BoringSSL\\QuicStream, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, length, IS_LONG, 0, "0")
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, timeout, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_quic_stream, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, stream, BoringSSL\\QuicStream, 0)
ZEND_END_ARG_INFO()

/* --------------------------------------------------------------------------
 * Method / function tables
 * ------------------------------------------------------------------------ */

static const zend_function_entry bssl_quic_conn_methods[] = {
    PHP_ME(QuicConnection, __construct, arginfo_quic_conn_construct, ZEND_ACC_PUBLIC)
    PHP_ME(QuicConnection, connect,     arginfo_quic_void,           ZEND_ACC_PUBLIC)
    PHP_ME(QuicConnection, isConnected, arginfo_quic_void,           ZEND_ACC_PUBLIC)
    PHP_ME(QuicConnection, openStream,  arginfo_quic_open_stream,    ZEND_ACC_PUBLIC)
    PHP_ME(QuicConnection, close,       arginfo_quic_void,           ZEND_ACC_PUBLIC)
    PHP_ME(QuicConnection, getAlpn,     arginfo_quic_void,           ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry bssl_quic_stream_methods[] = {
    PHP_ME(QuicStream, write,      arginfo_quic_stream_write, ZEND_ACC_PUBLIC)
    PHP_ME(QuicStream, read,       arginfo_quic_stream_read,  ZEND_ACC_PUBLIC)
    PHP_ME(QuicStream, conclude,   arginfo_quic_void,         ZEND_ACC_PUBLIC)
    PHP_ME(QuicStream, getId,      arginfo_quic_void,         ZEND_ACC_PUBLIC)
    PHP_ME(QuicStream, getType,    arginfo_quic_void,         ZEND_ACC_PUBLIC)
    PHP_ME(QuicStream, isReadable, arginfo_quic_void,         ZEND_ACC_PUBLIC)
    PHP_ME(QuicStream, isWritable, arginfo_quic_void,         ZEND_ACC_PUBLIC)
    PHP_FE_END
};

/* --------------------------------------------------------------------------
 * Registration (called from PHP_MINIT_FUNCTION in boringssl.c)
 * ------------------------------------------------------------------------ */

/* Procedural function table (registered separately from module functions) */
static const zend_function_entry bssl_quic_functions[] = {
    PHP_FE(boringssl_quic_connect,         arginfo_fn_quic_connect)
    PHP_FE(boringssl_quic_open_stream,     arginfo_fn_quic_open_stream)
    PHP_FE(boringssl_quic_stream_write,    arginfo_fn_quic_stream_write)
    PHP_FE(boringssl_quic_stream_read,     arginfo_fn_quic_stream_read)
    PHP_FE(boringssl_quic_stream_conclude, arginfo_fn_quic_stream)
    PHP_FE(boringssl_quic_close,           arginfo_fn_quic_conn)
    PHP_FE(boringssl_quic_is_connected,    arginfo_fn_quic_conn)
    PHP_FE_END
};

void bssl_quic_minit(int module_number) {
    zend_class_entry ce;

    /* QuicConnection */
    INIT_NS_CLASS_ENTRY(ce, "BoringSSL", "QuicConnection", bssl_quic_conn_methods);
    bssl_quic_conn_ce = zend_register_internal_class(&ce);
    bssl_quic_conn_ce->create_object = bssl_quic_conn_create;
    bssl_quic_conn_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NO_DYNAMIC_PROPERTIES;

    memcpy(&bssl_quic_conn_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    bssl_quic_conn_handlers.offset = XtOffsetOf(bssl_quic_conn_obj, std);
    bssl_quic_conn_handlers.free_obj = bssl_quic_conn_free;
    bssl_quic_conn_handlers.clone_obj = NULL;

    /* QuicStream */
    INIT_NS_CLASS_ENTRY(ce, "BoringSSL", "QuicStream", bssl_quic_stream_methods);
    bssl_quic_stream_ce = zend_register_internal_class(&ce);
    bssl_quic_stream_ce->create_object = bssl_quic_stream_create;
    bssl_quic_stream_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NO_DYNAMIC_PROPERTIES;

    memcpy(&bssl_quic_stream_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    bssl_quic_stream_handlers.offset = XtOffsetOf(bssl_quic_stream_obj, std);
    bssl_quic_stream_handlers.free_obj = bssl_quic_stream_free;
    bssl_quic_stream_handlers.clone_obj = NULL;

    /* Constants */
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "QUIC_STREAM_BIDI", BSSL_QUIC_STREAM_BIDI, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "QUIC_STREAM_UNI",  BSSL_QUIC_STREAM_UNI,  CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "QUIC_WRITE_FLAG_CONCLUDE", BSSL_QUIC_WRITE_FLAG_CONCLUDE, CONST_CS | CONST_PERSISTENT);

    /* Register procedural functions */
    zend_register_functions(NULL, bssl_quic_functions, NULL, MODULE_PERSISTENT);
}

#endif /* HAVE_BORINGSSL_QUIC */
