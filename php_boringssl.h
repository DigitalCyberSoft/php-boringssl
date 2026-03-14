/*
  +----------------------------------------------------------------------+
  | BoringSSL extension for PHP                                          |
  +----------------------------------------------------------------------+
  | Licensed under the ISC license (OpenSSL-compatible).                 |
  | BoringSSL itself is licensed under a mix of the ISC license,         |
  | the OpenSSL license, and the SSLeay license.                         |
  | See: https://boringssl.googlesource.com/boringssl/+/HEAD/LICENSE     |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_BORINGSSL_H
#define PHP_BORINGSSL_H

extern zend_module_entry boringssl_module_entry;
#define phpext_boringssl_ptr &boringssl_module_entry

#define PHP_BORINGSSL_VERSION "0.1.1"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/base.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#ifdef HAVE_BROTLI
#include <brotli/encode.h>
#include <brotli/decode.h>
#endif

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#if defined(ZTS) && defined(COMPILE_DL_BORINGSSL)
ZEND_TSRMLS_CACHE_EXTERN();
#endif

/* Deferred ALPS entry (applied per-SSL, not per-CTX) */
typedef struct _bssl_alps_entry {
    char *proto;
    size_t proto_len;
    char *settings;
    size_t settings_len;
    struct _bssl_alps_entry *next;
} bssl_alps_entry;

/* BoringSSL\Context object */
typedef struct _bssl_ctx_obj {
    SSL_CTX *ctx;
    zend_bool is_server;
    /* Deferred per-SSL config (BoringSSL requires these on SSL, not SSL_CTX) */
    bssl_alps_entry *alps_entries;
    zend_bool alps_use_new_codepoint;
    char *ech_config;
    size_t ech_config_len;
    FILE *keylog_fp;
    zend_object std;
} bssl_ctx_obj;

/* BoringSSL\Connection object */
typedef struct _bssl_conn_obj {
    SSL *ssl;
    BIO *bio;
    php_stream *stream;
    zval stream_zv;          /* prevents stream GC while SSL holds the fd */
    zend_object *ctx_zobj;   /* reference to parent Context */
    zend_bool ssl_active;
    zend_bool is_client;
    zend_object std;
} bssl_conn_obj;

/* BoringSSL\Session object */
typedef struct _bssl_session_obj {
    SSL_SESSION *session;
    zend_object std;
} bssl_session_obj;

/* Object conversion helpers */
static inline bssl_ctx_obj *bssl_ctx_from_obj(zend_object *obj) {
    return (bssl_ctx_obj *)((char *)obj - XtOffsetOf(bssl_ctx_obj, std));
}

static inline bssl_conn_obj *bssl_conn_from_obj(zend_object *obj) {
    return (bssl_conn_obj *)((char *)obj - XtOffsetOf(bssl_conn_obj, std));
}

static inline bssl_session_obj *bssl_session_from_obj(zend_object *obj) {
    return (bssl_session_obj *)((char *)obj - XtOffsetOf(bssl_session_obj, std));
}

#define Z_BSSL_CTX_P(zv)     bssl_ctx_from_obj(Z_OBJ_P(zv))
#define Z_BSSL_CONN_P(zv)    bssl_conn_from_obj(Z_OBJ_P(zv))
#define Z_BSSL_SESSION_P(zv) bssl_session_from_obj(Z_OBJ_P(zv))

/* Class entries */
extern zend_class_entry *bssl_ctx_ce;
extern zend_class_entry *bssl_conn_ce;
extern zend_class_entry *bssl_session_ce;
extern zend_class_entry *bssl_exception_ce;

/* Error helper */
static inline void bssl_throw_ssl_error(const char *prefix) {
    unsigned long err = ERR_peek_last_error();
    if (err) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        zend_throw_exception_ex(bssl_exception_ce, 0, "%s: %s", prefix, buf);
        ERR_clear_error();
    } else {
        zend_throw_exception(bssl_exception_ce, prefix, 0);
    }
}

/* QUIC transport via ngtcp2 (conditionally compiled) */
#ifdef HAVE_BORINGSSL_QUIC
#include "quic.h"
#endif

#endif /* PHP_BORINGSSL_H */
