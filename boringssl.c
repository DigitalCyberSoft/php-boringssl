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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/spl/spl_exceptions.h"
#include "zend_exceptions.h"
#include "zend_smart_str.h"
#include "php_network.h"
#include "php_streams.h"

#include "php_boringssl.h"

/* Class entries */
zend_class_entry *bssl_ctx_ce;
zend_class_entry *bssl_conn_ce;
zend_class_entry *bssl_session_ce;
zend_class_entry *bssl_exception_ce;

/* Object handlers */
static zend_object_handlers bssl_ctx_handlers;
static zend_object_handlers bssl_conn_handlers;
static zend_object_handlers bssl_session_handlers;

static int bssl_ctx_ex_data_idx = -1;

/* --------------------------------------------------------------------------
 * Certificate compression callbacks
 * ------------------------------------------------------------------------ */

/* RFC 8879 limits uncompressed cert to 2^24-1; cap at 16 MiB for safety */
#define BSSL_CERT_DECOMPRESS_MAX (16 * 1024 * 1024)

#ifdef HAVE_BROTLI
static int bssl_cert_compress_brotli(SSL *ssl, CBB *out,
        const uint8_t *in, size_t in_len) {
    size_t max_out = BrotliEncoderMaxCompressedSize(in_len);
    uint8_t *dest;
    if (!CBB_reserve(out, &dest, max_out)) return 0;
    size_t encoded_size = max_out;
    if (!BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
            BROTLI_DEFAULT_MODE, in_len, in, &encoded_size, dest)) {
        return 0;
    }
    if (!CBB_did_write(out, encoded_size)) return 0;
    return 1;
}

static int bssl_cert_decompress_brotli(SSL *ssl, CRYPTO_BUFFER **out,
        size_t uncompressed_len, const uint8_t *in, size_t in_len) {
    if (uncompressed_len > BSSL_CERT_DECOMPRESS_MAX) return 0;
    uint8_t *data = OPENSSL_malloc(uncompressed_len);
    if (!data) return 0;
    size_t decoded_size = uncompressed_len;
    if (BrotliDecoderDecompress(in_len, in, &decoded_size, data) !=
            BROTLI_DECODER_RESULT_SUCCESS || decoded_size != uncompressed_len) {
        OPENSSL_free(data);
        return 0;
    }
    *out = CRYPTO_BUFFER_new(data, uncompressed_len, NULL);
    OPENSSL_free(data);
    return *out != NULL;
}
#endif

#ifdef HAVE_ZLIB
static int bssl_cert_compress_zlib(SSL *ssl, CBB *out,
        const uint8_t *in, size_t in_len) {
    uLongf max_out = compressBound(in_len);
    uint8_t *dest;
    if (!CBB_reserve(out, &dest, max_out)) return 0;
    if (compress(dest, &max_out, in, in_len) != Z_OK) return 0;
    if (!CBB_did_write(out, max_out)) return 0;
    return 1;
}

static int bssl_cert_decompress_zlib(SSL *ssl, CRYPTO_BUFFER **out,
        size_t uncompressed_len, const uint8_t *in, size_t in_len) {
    if (uncompressed_len > BSSL_CERT_DECOMPRESS_MAX) return 0;
    uint8_t *data = OPENSSL_malloc(uncompressed_len);
    if (!data) return 0;
    uLongf dest_len = uncompressed_len;
    if (uncompress(data, &dest_len, in, in_len) != Z_OK ||
            dest_len != uncompressed_len) {
        OPENSSL_free(data);
        return 0;
    }
    *out = CRYPTO_BUFFER_new(data, uncompressed_len, NULL);
    OPENSSL_free(data);
    return *out != NULL;
}
#endif

#ifdef HAVE_ZSTD
static int bssl_cert_compress_zstd(SSL *ssl, CBB *out,
        const uint8_t *in, size_t in_len) {
    size_t max_out = ZSTD_compressBound(in_len);
    uint8_t *dest;
    if (!CBB_reserve(out, &dest, max_out)) return 0;
    size_t result = ZSTD_compress(dest, max_out, in, in_len,
            ZSTD_CLEVEL_DEFAULT);
    if (ZSTD_isError(result)) return 0;
    if (!CBB_did_write(out, result)) return 0;
    return 1;
}

static int bssl_cert_decompress_zstd(SSL *ssl, CRYPTO_BUFFER **out,
        size_t uncompressed_len, const uint8_t *in, size_t in_len) {
    if (uncompressed_len > BSSL_CERT_DECOMPRESS_MAX) return 0;
    uint8_t *data = OPENSSL_malloc(uncompressed_len);
    if (!data) return 0;
    size_t result = ZSTD_decompress(data, uncompressed_len, in, in_len);
    if (ZSTD_isError(result) || result != uncompressed_len) {
        OPENSSL_free(data);
        return 0;
    }
    *out = CRYPTO_BUFFER_new(data, uncompressed_len, NULL);
    OPENSSL_free(data);
    return *out != NULL;
}
#endif

/* --------------------------------------------------------------------------
 * Arginfo definitions
 * ------------------------------------------------------------------------ */

/* Context methods */
ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_cipher_list, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, ciphers, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_cipher_suites, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, suites, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_alpn, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, protocols, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_groups_list, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, groups, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_sigalgs, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, algIds, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_bool, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, enabled, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_add_app_settings, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, proto, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, settings, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_add_cert_compression, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, algId, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_ech, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, echConfigList, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_proto_version, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, version, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_verify, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, mode, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, callback, IS_CALLABLE, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_use_cert_file, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_load_verify, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, caFile, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, caPath, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_session_cache_mode, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, mode, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_callback, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, callback, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

/* Connection methods */
ZEND_BEGIN_ARG_INFO_EX(arginfo_conn_set_stream, 0, 0, 1)
    ZEND_ARG_INFO(0, stream)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_conn_set_fd, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, fd, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_conn_read, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_conn_write, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_conn_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_conn_get_peer_app_settings, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, proto, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_conn_set_session, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, session, BoringSSL\\Session, 0)
ZEND_END_ARG_INFO()

/* Session methods */
ZEND_BEGIN_ARG_INFO_EX(arginfo_session_from_bytes, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, bytes, IS_STRING, 0)
    ZEND_ARG_OBJ_INFO(0, ctx, BoringSSL\\Context, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_session_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ctx_set_pem_string, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, pem, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_conn_set_hostname, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, hostname, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_conn_set_reneg_mode, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, mode, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_conn_export_keying_material, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, label, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, context, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

/* --------------------------------------------------------------------------
 * Context object handlers
 * ------------------------------------------------------------------------ */

static zend_object *bssl_ctx_create(zend_class_entry *ce) {
    bssl_ctx_obj *obj = zend_object_alloc(sizeof(bssl_ctx_obj), ce);
    zend_object_std_init(&obj->std, ce);
    object_properties_init(&obj->std, ce);
    obj->std.handlers = &bssl_ctx_handlers;
    obj->ctx = NULL;
    obj->is_server = 0;
    obj->alps_entries = NULL;
    obj->alps_use_new_codepoint = 0;
    obj->ech_config = NULL;
    obj->ech_config_len = 0;
    obj->keylog_fp = NULL;
    return &obj->std;
}

static void bssl_ctx_free(zend_object *object) {
    bssl_ctx_obj *obj = bssl_ctx_from_obj(object);
    if (obj->ctx) {
        SSL_CTX_free(obj->ctx);
        obj->ctx = NULL;
    }
    /* Free ALPS entries */
    bssl_alps_entry *entry = obj->alps_entries;
    while (entry) {
        bssl_alps_entry *next = entry->next;
        efree(entry->proto);
        efree(entry->settings);
        efree(entry);
        entry = next;
    }
    obj->alps_entries = NULL;
    if (obj->ech_config) {
        efree(obj->ech_config);
        obj->ech_config = NULL;
    }
    if (obj->keylog_fp) {
        fclose(obj->keylog_fp);
        obj->keylog_fp = NULL;
    }
    zend_object_std_dtor(&obj->std);
}

/* --------------------------------------------------------------------------
 * Connection object handlers
 * ------------------------------------------------------------------------ */

static zend_object *bssl_conn_create(zend_class_entry *ce) {
    bssl_conn_obj *obj = zend_object_alloc(sizeof(bssl_conn_obj), ce);
    zend_object_std_init(&obj->std, ce);
    object_properties_init(&obj->std, ce);
    obj->std.handlers = &bssl_conn_handlers;
    obj->ssl = NULL;
    obj->bio = NULL;
    obj->stream = NULL;
    ZVAL_UNDEF(&obj->stream_zv);
    obj->ctx_zobj = NULL;
    obj->ssl_active = 0;
    obj->is_client = 1;
    return &obj->std;
}

static void bssl_conn_free(zend_object *object) {
    bssl_conn_obj *obj = bssl_conn_from_obj(object);
    if (obj->ssl) {
        SSL_free(obj->ssl);
        obj->ssl = NULL;
    }
    if (!Z_ISUNDEF(obj->stream_zv)) {
        zval_ptr_dtor(&obj->stream_zv);
        ZVAL_UNDEF(&obj->stream_zv);
    }
    if (obj->ctx_zobj) {
        OBJ_RELEASE(obj->ctx_zobj);
        obj->ctx_zobj = NULL;
    }
    zend_object_std_dtor(&obj->std);
}

/* --------------------------------------------------------------------------
 * Session object handlers
 * ------------------------------------------------------------------------ */

static zend_object *bssl_session_create(zend_class_entry *ce) {
    bssl_session_obj *obj = zend_object_alloc(sizeof(bssl_session_obj), ce);
    zend_object_std_init(&obj->std, ce);
    object_properties_init(&obj->std, ce);
    obj->std.handlers = &bssl_session_handlers;
    obj->session = NULL;
    return &obj->std;
}

static void bssl_session_free(zend_object *object) {
    bssl_session_obj *obj = bssl_session_from_obj(object);
    if (obj->session) {
        SSL_SESSION_free(obj->session);
        obj->session = NULL;
    }
    zend_object_std_dtor(&obj->std);
}

static void bssl_keylog_callback(const SSL *ssl, const char *line) {
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    if (!ctx) return;
    bssl_ctx_obj *obj = SSL_CTX_get_ex_data(ctx, bssl_ctx_ex_data_idx);
    if (!obj || !obj->keylog_fp) return;
    fprintf(obj->keylog_fp, "%s\n", line);
    fflush(obj->keylog_fp);
}

/* --------------------------------------------------------------------------
 * Context methods
 * ------------------------------------------------------------------------ */

PHP_METHOD(Context, new) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);

    if (obj->ctx) {
        zend_throw_exception(bssl_exception_ce,
            "Context already initialized", 0);
        RETURN_THROWS();
    }

    ERR_clear_error();
    obj->ctx = SSL_CTX_new(TLS_client_method());
    if (!obj->ctx) {
        bssl_throw_ssl_error("Failed to create SSL context");
        RETURN_THROWS();
    }
    obj->is_server = 0;

    SSL_CTX_set_ex_data(obj->ctx, bssl_ctx_ex_data_idx, obj);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, newServer) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);

    if (obj->ctx) {
        zend_throw_exception(bssl_exception_ce,
            "Context already initialized", 0);
        RETURN_THROWS();
    }

    ERR_clear_error();
    obj->ctx = SSL_CTX_new(TLS_server_method());
    if (!obj->ctx) {
        bssl_throw_ssl_error("Failed to create SSL server context");
        RETURN_THROWS();
    }
    obj->is_server = 1;

    SSL_CTX_set_ex_data(obj->ctx, bssl_ctx_ex_data_idx, obj);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

#define BSSL_CTX_CHECK(obj) \
    do { \
        if (!(obj)->ctx) { \
            zend_throw_exception(bssl_exception_ce, \
                "Context not initialized. Call Context::new() or Context::newServer() first", 0); \
            RETURN_THROWS(); \
        } \
    } while (0)

PHP_METHOD(Context, setCipherList) {
    char *ciphers;
    size_t ciphers_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(ciphers, ciphers_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    if (SSL_CTX_set_cipher_list(obj->ctx, ciphers) != 1) {
        bssl_throw_ssl_error("Failed to set cipher list");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setCipherSuites) {
    char *suites;
    size_t suites_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(suites, suites_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    /* BoringSSL does not allow configuring TLS 1.3 cipher suites separately.
     * TLS 1.3 ciphers have a built-in preference order and are always all
     * enabled. This method is accepted for API compatibility but is a no-op.
     * This is a fundamental difference from OpenSSL. */
    php_error_docref(NULL, E_NOTICE,
        "BoringSSL does not support configuring TLS 1.3 cipher suites. "
        "TLS 1.3 ciphers have a built-in preference order and are always enabled. "
        "Use setCipherList() for TLS 1.2 cipher control.");

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setAlpnProtos) {
    zval *protocols;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(protocols)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    /* Build wire-format ALPN: each protocol prefixed with its length byte */
    smart_str alpn_buf = {0};
    zval *entry;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(protocols), entry) {
        zend_string *proto = zval_get_string(entry);
        if (ZSTR_LEN(proto) > 255 || ZSTR_LEN(proto) == 0) {
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

    if (!alpn_buf.s || !ZSTR_LEN(alpn_buf.s)) {
        smart_str_free(&alpn_buf);
        zend_throw_exception(zend_ce_value_error,
            "ALPN protocol list must not be empty", 0);
        RETURN_THROWS();
    }

    smart_str_0(&alpn_buf);
    int ret = SSL_CTX_set_alpn_protos(obj->ctx,
        (const uint8_t *)ZSTR_VAL(alpn_buf.s), ZSTR_LEN(alpn_buf.s));
    smart_str_free(&alpn_buf);

    if (ret != 0) {
        bssl_throw_ssl_error("Failed to set ALPN protocols");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setGroupsList) {
    char *groups;
    size_t groups_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(groups, groups_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    if (SSL_CTX_set1_groups_list(obj->ctx, groups) != 1) {
        bssl_throw_ssl_error("Failed to set supported groups");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setVerifyAlgorithmPrefs) {
    zval *alg_ids;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(alg_ids)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    HashTable *ht = Z_ARRVAL_P(alg_ids);
    uint32_t count = zend_hash_num_elements(ht);
    if (count == 0) {
        zend_throw_exception(zend_ce_value_error,
            "Algorithm preferences array must not be empty", 0);
        RETURN_THROWS();
    }

    uint16_t *prefs = ecalloc(count, sizeof(uint16_t));
    uint32_t i = 0;
    zval *entry;
    ZEND_HASH_FOREACH_VAL(ht, entry) {
        zend_long val = zval_get_long(entry);
        if (val < 0 || val > 0xFFFF) {
            efree(prefs);
            zend_throw_exception_ex(zend_ce_value_error, 0,
                "Algorithm ID must be between 0 and 65535, got " ZEND_LONG_FMT, val);
            RETURN_THROWS();
        }
        prefs[i++] = (uint16_t)val;
    } ZEND_HASH_FOREACH_END();

    if (!SSL_CTX_set_verify_algorithm_prefs(obj->ctx, prefs, count)) {
        efree(prefs);
        bssl_throw_ssl_error("Failed to set verify algorithm preferences");
        RETURN_THROWS();
    }

    efree(prefs);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setSigningAlgorithmPrefs) {
    zval *alg_ids;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(alg_ids)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    HashTable *ht = Z_ARRVAL_P(alg_ids);
    uint32_t count = zend_hash_num_elements(ht);
    if (count == 0) {
        zend_throw_exception(zend_ce_value_error,
            "Algorithm preferences array must not be empty", 0);
        RETURN_THROWS();
    }

    uint16_t *prefs = ecalloc(count, sizeof(uint16_t));
    uint32_t i = 0;
    zval *entry;
    ZEND_HASH_FOREACH_VAL(ht, entry) {
        zend_long val = zval_get_long(entry);
        if (val < 0 || val > 0xFFFF) {
            efree(prefs);
            zend_throw_exception_ex(zend_ce_value_error, 0,
                "Algorithm ID must be between 0 and 65535, got " ZEND_LONG_FMT, val);
            RETURN_THROWS();
        }
        prefs[i++] = (uint16_t)val;
    } ZEND_HASH_FOREACH_END();

    if (!SSL_CTX_set_signing_algorithm_prefs(obj->ctx, prefs, count)) {
        efree(prefs);
        bssl_throw_ssl_error("Failed to set signing algorithm preferences");
        RETURN_THROWS();
    }

    efree(prefs);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setGreaseEnabled) {
    zend_bool enabled;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_BOOL(enabled)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    SSL_CTX_set_grease_enabled(obj->ctx, enabled ? 1 : 0);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setPermuteExtensions) {
    zend_bool enabled;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_BOOL(enabled)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    SSL_CTX_set_permute_extensions(obj->ctx, enabled ? 1 : 0);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, addApplicationSettings) {
    char *proto, *settings;
    size_t proto_len, settings_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(proto, proto_len)
        Z_PARAM_STRING(settings, settings_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    /* BoringSSL's SSL_add_application_settings operates on SSL, not SSL_CTX.
     * Store the config and apply it when creating each connection. */
    bssl_alps_entry *entry = ecalloc(1, sizeof(bssl_alps_entry));
    entry->proto = estrndup(proto, proto_len);
    entry->proto_len = proto_len;
    entry->settings = estrndup(settings, settings_len);
    entry->settings_len = settings_len;
    entry->next = obj->alps_entries;
    obj->alps_entries = entry;

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setAlpsUseNewCodepoint) {
    zend_bool use_new;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_BOOL(use_new)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    /* BoringSSL's SSL_set_alps_use_new_codepoint operates on SSL, not SSL_CTX.
     * Store and apply when creating each connection. */
    obj->alps_use_new_codepoint = use_new;

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, addCertCompressionAlg) {
    zend_long alg_id;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(alg_id)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    int ok = 0;
    switch (alg_id) {
#ifdef HAVE_BROTLI
        case 2: /* CERT_COMPRESS_BROTLI */
            ok = SSL_CTX_add_cert_compression_alg(obj->ctx,
                2, bssl_cert_compress_brotli, bssl_cert_decompress_brotli);
            break;
#endif
#ifdef HAVE_ZLIB
        case 1: /* CERT_COMPRESS_ZLIB */
            ok = SSL_CTX_add_cert_compression_alg(obj->ctx,
                1, bssl_cert_compress_zlib, bssl_cert_decompress_zlib);
            break;
#endif
#ifdef HAVE_ZSTD
        case 3: /* CERT_COMPRESS_ZSTD */
            ok = SSL_CTX_add_cert_compression_alg(obj->ctx,
                3, bssl_cert_compress_zstd, bssl_cert_decompress_zstd);
            break;
#endif
        default:
            zend_throw_exception_ex(zend_ce_value_error, 0,
                "Unsupported certificate compression algorithm: " ZEND_LONG_FMT, alg_id);
            RETURN_THROWS();
    }

    if (!ok) {
        bssl_throw_ssl_error("Failed to add certificate compression algorithm");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setEchConfigList) {
    char *ech_config;
    size_t ech_config_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(ech_config, ech_config_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    /* BoringSSL's SSL_set1_ech_config_list operates on SSL, not SSL_CTX.
     * Store and apply when creating each connection. */
    if (obj->ech_config) {
        efree(obj->ech_config);
    }
    obj->ech_config = estrndup(ech_config, ech_config_len);
    obj->ech_config_len = ech_config_len;

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setMinProtoVersion) {
    zend_long version;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(version)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    if (version < 0 || version > 0xFFFF) {
        zend_throw_exception(zend_ce_value_error,
            "Protocol version must be between 0 and 65535", 0);
        RETURN_THROWS();
    }

    if (!SSL_CTX_set_min_proto_version(obj->ctx, (uint16_t)version)) {
        bssl_throw_ssl_error("Failed to set minimum protocol version");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setMaxProtoVersion) {
    zend_long version;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(version)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    if (version < 0 || version > 0xFFFF) {
        zend_throw_exception(zend_ce_value_error,
            "Protocol version must be between 0 and 65535", 0);
        RETURN_THROWS();
    }

    if (!SSL_CTX_set_max_proto_version(obj->ctx, (uint16_t)version)) {
        bssl_throw_ssl_error("Failed to set maximum protocol version");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setEarlyDataEnabled) {
    zend_bool enabled;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_BOOL(enabled)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    SSL_CTX_set_early_data_enabled(obj->ctx, enabled ? 1 : 0);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, useCertificateFile) {
    char *path;
    size_t path_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    if (php_check_open_basedir(path)) {
        RETURN_THROWS();
    }

    if (SSL_CTX_use_certificate_file(obj->ctx, path, SSL_FILETYPE_PEM) != 1) {
        bssl_throw_ssl_error("Failed to load certificate file");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, useCertificateChainFile) {
    char *path;
    size_t path_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    if (php_check_open_basedir(path)) {
        RETURN_THROWS();
    }

    if (SSL_CTX_use_certificate_chain_file(obj->ctx, path) != 1) {
        bssl_throw_ssl_error("Failed to load certificate chain file");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, usePrivateKeyFile) {
    char *path;
    size_t path_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    if (php_check_open_basedir(path)) {
        RETURN_THROWS();
    }

    if (SSL_CTX_use_PrivateKey_file(obj->ctx, path, SSL_FILETYPE_PEM) != 1) {
        bssl_throw_ssl_error("Failed to load private key file");
        RETURN_THROWS();
    }

    if (SSL_CTX_check_private_key(obj->ctx) != 1) {
        bssl_throw_ssl_error("Private key does not match certificate");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, loadVerifyLocations) {
    char *ca_file;
    size_t ca_file_len;
    char *ca_path = NULL;
    size_t ca_path_len = 0;
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(ca_file, ca_file_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_STRING_OR_NULL(ca_path, ca_path_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    if (php_check_open_basedir(ca_file)) {
        RETURN_THROWS();
    }
    if (ca_path && php_check_open_basedir(ca_path)) {
        RETURN_THROWS();
    }

    if (SSL_CTX_load_verify_locations(obj->ctx, ca_file,
            ca_path_len > 0 ? ca_path : NULL) != 1) {
        bssl_throw_ssl_error("Failed to load verify locations");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setVerify) {
    zend_long mode;
    zval *callback = NULL;
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_LONG(mode)
        Z_PARAM_OPTIONAL
        Z_PARAM_ZVAL_OR_NULL(callback)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    if (callback && Z_TYPE_P(callback) != IS_NULL) {
        zend_throw_exception(bssl_exception_ce,
            "Verify callbacks are not yet supported", 0);
        RETURN_THROWS();
    }

    SSL_CTX_set_verify(obj->ctx, (int)mode, NULL);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setSessionCacheMode) {
    zend_long mode;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(mode)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);

    SSL_CTX_set_session_cache_mode(obj->ctx, (int)mode);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setDefaultVerifyPaths) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    if (!SSL_CTX_set_default_verify_paths(obj->ctx)) {
        bssl_throw_ssl_error("Failed to set default verify paths");
        RETURN_THROWS();
    }
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setVerifyDepth) {
    zend_long depth;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(depth)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    if (depth < 0 || depth > 100) {
        zend_throw_exception(zend_ce_value_error,
            "Verify depth must be between 0 and 100", 0);
        RETURN_THROWS();
    }
    SSL_CTX_set_verify_depth(obj->ctx, (int)depth);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setOptions) {
    zend_long options;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(options)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    if (options < 0 || options > UINT32_MAX) {
        zend_throw_exception(zend_ce_value_error,
            "Options must be a valid 32-bit unsigned value", 0);
        RETURN_THROWS();
    }
    SSL_CTX_set_options(obj->ctx, (uint32_t)options);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, clearOptions) {
    zend_long options;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(options)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    if (options < 0 || options > UINT32_MAX) {
        zend_throw_exception(zend_ce_value_error,
            "Options must be a valid 32-bit unsigned value", 0);
        RETURN_THROWS();
    }
    SSL_CTX_clear_options(obj->ctx, (uint32_t)options);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, getOptions) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    RETURN_LONG((zend_long)SSL_CTX_get_options(obj->ctx));
}

PHP_METHOD(Context, enableOcspStapling) {
    zend_bool enabled;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_BOOL(enabled)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    if (enabled) {
        SSL_CTX_enable_ocsp_stapling(obj->ctx);
    }
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, enableSignedCertTimestamps) {
    zend_bool enabled;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_BOOL(enabled)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    if (enabled) {
        SSL_CTX_enable_signed_cert_timestamps(obj->ctx);
    }
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setKeylogFile) {
    char *path;
    size_t path_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    if (php_check_open_basedir(path)) {
        RETURN_THROWS();
    }
    if (obj->keylog_fp) {
        fclose(obj->keylog_fp);
        obj->keylog_fp = NULL;
    }
    obj->keylog_fp = fopen(path, "a");
    if (!obj->keylog_fp) {
        zend_throw_exception_ex(bssl_exception_ce, 0,
            "Failed to open keylog file: %s", path);
        RETURN_THROWS();
    }
    SSL_CTX_set_keylog_callback(obj->ctx, bssl_keylog_callback);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, loadClientCAFile) {
    char *path;
    size_t path_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    if (php_check_open_basedir(path)) {
        RETURN_THROWS();
    }
    STACK_OF(X509_NAME) *ca_list = SSL_load_client_CA_file(path);
    if (!ca_list) {
        bssl_throw_ssl_error("Failed to load client CA file");
        RETURN_THROWS();
    }
    SSL_CTX_set_client_CA_list(obj->ctx, ca_list);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, setSessionTicketKeys) {
    char *keys;
    size_t keys_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(keys, keys_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    if (keys_len != 48) {
        zend_throw_exception(zend_ce_value_error,
            "Session ticket keys must be exactly 48 bytes", 0);
        RETURN_THROWS();
    }
    if (!SSL_CTX_set_tlsext_ticket_keys(obj->ctx, keys, 48)) {
        bssl_throw_ssl_error("Failed to set session ticket keys");
        RETURN_THROWS();
    }
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, useCertificateChainPem) {
    char *pem;
    size_t pem_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(pem, pem_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    if (pem_len > INT_MAX) {
        zend_throw_exception(zend_ce_value_error, "PEM data too large", 0);
        RETURN_THROWS();
    }
    BIO *bio = BIO_new_mem_buf(pem, (int)pem_len);
    if (!bio) {
        bssl_throw_ssl_error("Failed to create BIO");
        RETURN_THROWS();
    }
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(bio);
        bssl_throw_ssl_error("Failed to read certificate from PEM");
        RETURN_THROWS();
    }
    if (SSL_CTX_use_certificate(obj->ctx, cert) != 1) {
        X509_free(cert);
        BIO_free(bio);
        bssl_throw_ssl_error("Failed to set certificate");
        RETURN_THROWS();
    }
    X509_free(cert);
    SSL_CTX_clear_extra_chain_certs(obj->ctx);
    while (1) {
        X509 *chain_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (!chain_cert) break;
        if (!SSL_CTX_add_extra_chain_cert(obj->ctx, chain_cert)) {
            X509_free(chain_cert);
            BIO_free(bio);
            bssl_throw_ssl_error("Failed to add chain certificate");
            RETURN_THROWS();
        }
    }
    ERR_clear_error();
    BIO_free(bio);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, usePrivateKeyPem) {
    char *pem;
    size_t pem_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(pem, pem_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(obj);
    if (pem_len > INT_MAX) {
        zend_throw_exception(zend_ce_value_error, "PEM data too large", 0);
        RETURN_THROWS();
    }
    BIO *bio = BIO_new_mem_buf(pem, (int)pem_len);
    if (!bio) {
        bssl_throw_ssl_error("Failed to create BIO");
        RETURN_THROWS();
    }
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        bssl_throw_ssl_error("Failed to read private key from PEM");
        RETURN_THROWS();
    }
    if (SSL_CTX_use_PrivateKey(obj->ctx, pkey) != 1) {
        EVP_PKEY_free(pkey);
        bssl_throw_ssl_error("Failed to set private key");
        RETURN_THROWS();
    }
    EVP_PKEY_free(pkey);
    if (SSL_CTX_check_private_key(obj->ctx) != 1) {
        bssl_throw_ssl_error("Private key does not match certificate");
        RETURN_THROWS();
    }
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Context, newConnection) {
    ZEND_PARSE_PARAMETERS_NONE();

    bssl_ctx_obj *ctx_obj = Z_BSSL_CTX_P(ZEND_THIS);
    BSSL_CTX_CHECK(ctx_obj);

    object_init_ex(return_value, bssl_conn_ce);
    bssl_conn_obj *conn = Z_BSSL_CONN_P(return_value);

    ERR_clear_error();
    conn->ssl = SSL_new(ctx_obj->ctx);
    if (!conn->ssl) {
        bssl_throw_ssl_error("Failed to create SSL connection");
        RETURN_THROWS();
    }

    conn->is_client = !ctx_obj->is_server;

    /* Apply deferred per-SSL settings from context */

    /* ALPS new codepoint */
    if (ctx_obj->alps_use_new_codepoint) {
        SSL_set_alps_use_new_codepoint(conn->ssl, 1);
    }

    /* ALPS entries */
    bssl_alps_entry *entry = ctx_obj->alps_entries;
    while (entry) {
        if (!SSL_add_application_settings(conn->ssl,
                (const uint8_t *)entry->proto, entry->proto_len,
                (const uint8_t *)entry->settings, entry->settings_len)) {
            SSL_free(conn->ssl);
            conn->ssl = NULL;
            bssl_throw_ssl_error("Failed to add application settings to connection");
            RETURN_THROWS();
        }
        entry = entry->next;
    }

    /* ECH config */
    if (ctx_obj->ech_config && ctx_obj->ech_config_len > 0) {
        if (!SSL_set1_ech_config_list(conn->ssl,
                (const uint8_t *)ctx_obj->ech_config, ctx_obj->ech_config_len)) {
            SSL_free(conn->ssl);
            conn->ssl = NULL;
            bssl_throw_ssl_error("Failed to set ECH config on connection");
            RETURN_THROWS();
        }
    }

    /* Hold a reference to the context */
    conn->ctx_zobj = Z_OBJ_P(ZEND_THIS);
    GC_ADDREF(conn->ctx_zobj);
}

/* --------------------------------------------------------------------------
 * Connection methods
 * ------------------------------------------------------------------------ */

#define BSSL_CONN_CHECK(obj) \
    do { \
        if (!(obj)->ssl) { \
            zend_throw_exception(bssl_exception_ce, \
                "Connection not initialized", 0); \
            RETURN_THROWS(); \
        } \
    } while (0)

PHP_METHOD(Connection, setFd) {
    zend_long fd;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(fd)
    ZEND_PARSE_PARAMETERS_END();

    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    if (fd < 0 || fd > INT_MAX) {
        zend_throw_exception(zend_ce_value_error,
            "Invalid file descriptor", 0);
        RETURN_THROWS();
    }

    if (!SSL_set_fd(obj->ssl, (int)fd)) {
        bssl_throw_ssl_error("Failed to set file descriptor");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Connection, setStream) {
    zval *zstream;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(zstream)
    ZEND_PARSE_PARAMETERS_END();

    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    php_stream *stream;
    php_stream_from_zval(stream, zstream);

    void *fd_ptr;
    if (php_stream_cast(stream, PHP_STREAM_AS_FD, &fd_ptr, 1) == FAILURE) {
        zend_throw_exception(bssl_exception_ce,
            "Could not extract file descriptor from stream", 0);
        RETURN_THROWS();
    }
    int fd = (int)(intptr_t)fd_ptr;

    if (!SSL_set_fd(obj->ssl, fd)) {
        bssl_throw_ssl_error("Failed to attach stream");
        RETURN_THROWS();
    }

    /* Release any previously held stream reference */
    if (!Z_ISUNDEF(obj->stream_zv)) {
        zval_ptr_dtor(&obj->stream_zv);
    }

    obj->stream = stream;
    ZVAL_COPY(&obj->stream_zv, zstream);

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Connection, connect) {
    ZEND_PARSE_PARAMETERS_NONE();

    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    ERR_clear_error();
    int ret = SSL_connect(obj->ssl);
    if (ret != 1) {
        int err = SSL_get_error(obj->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            RETURN_FALSE;
        }
        bssl_throw_ssl_error("SSL handshake failed");
        RETURN_THROWS();
    }

    obj->ssl_active = 1;
    RETURN_TRUE;
}

PHP_METHOD(Connection, accept) {
    ZEND_PARSE_PARAMETERS_NONE();

    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    ERR_clear_error();
    int ret = SSL_accept(obj->ssl);
    if (ret != 1) {
        int err = SSL_get_error(obj->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            RETURN_FALSE;
        }
        bssl_throw_ssl_error("SSL accept failed");
        RETURN_THROWS();
    }

    obj->ssl_active = 1;
    RETURN_TRUE;
}

PHP_METHOD(Connection, read) {
    zend_long length;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END();

    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    if (length <= 0 || length > INT_MAX) {
        zend_throw_exception(zend_ce_value_error,
            "Read length must be between 1 and " ZEND_TOSTR(INT_MAX), 0);
        RETURN_THROWS();
    }

    zend_string *buf = zend_string_alloc(length, 0);
    ERR_clear_error();
    int bytes = SSL_read(obj->ssl, ZSTR_VAL(buf), (int)length);
    if (bytes <= 0) {
        zend_string_release(buf);
        int err = SSL_get_error(obj->ssl, bytes);
        if (err == SSL_ERROR_ZERO_RETURN) {
            RETURN_FALSE;
        }
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            RETURN_EMPTY_STRING();
        }
        bssl_throw_ssl_error("SSL read failed");
        RETURN_THROWS();
    }

    ZSTR_LEN(buf) = bytes;
    ZSTR_VAL(buf)[bytes] = '\0';
    RETURN_NEW_STR(buf);
}

PHP_METHOD(Connection, write) {
    char *data;
    size_t data_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(data, data_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    if (data_len > INT_MAX) {
        zend_throw_exception(zend_ce_value_error,
            "Data too large for single SSL_write", 0);
        RETURN_THROWS();
    }

    ERR_clear_error();
    int bytes = SSL_write(obj->ssl, data, (int)data_len);
    if (bytes <= 0) {
        int err = SSL_get_error(obj->ssl, bytes);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            RETURN_LONG(0);
        }
        bssl_throw_ssl_error("SSL write failed");
        RETURN_THROWS();
    }

    RETURN_LONG(bytes);
}

PHP_METHOD(Connection, writeEarlyData) {
    char *data;
    size_t data_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(data, data_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    if (data_len > INT_MAX) {
        zend_throw_exception(zend_ce_value_error,
            "Data too large for single SSL_write", 0);
        RETURN_THROWS();
    }

    /* In BoringSSL, early data is written via SSL_write during the handshake
     * when SSL_in_early_data() is true. The caller must have enabled early data
     * on the context and be in the early data state. */
    if (!SSL_in_early_data(obj->ssl)) {
        zend_throw_exception(bssl_exception_ce,
            "Not in early data state. Ensure early data is enabled and "
            "a resumption session is set before calling connect()", 0);
        RETURN_THROWS();
    }

    ERR_clear_error();
    int bytes = SSL_write(obj->ssl, data, (int)data_len);
    if (bytes <= 0) {
        bssl_throw_ssl_error("Failed to write early data");
        RETURN_THROWS();
    }

    RETURN_LONG(bytes);
}

PHP_METHOD(Connection, pending) {
    ZEND_PARSE_PARAMETERS_NONE();

    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    RETURN_LONG(SSL_pending(obj->ssl));
}

PHP_METHOD(Connection, shutdown) {
    ZEND_PARSE_PARAMETERS_NONE();

    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    int ret = SSL_shutdown(obj->ssl);
    if (ret < 0) {
        bssl_throw_ssl_error("SSL shutdown failed");
        RETURN_THROWS();
    }

    obj->ssl_active = 0;
    RETURN_BOOL(ret == 1);
}

PHP_METHOD(Connection, getError) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    /* SSL_get_error requires the return value of the last SSL I/O call.
     * Passing 0 queries the error state without implying a specific failure. */
    RETURN_LONG(SSL_get_error(obj->ssl, 0));
}

PHP_METHOD(Connection, getErrorString) {
    ZEND_PARSE_PARAMETERS_NONE();

    unsigned long err = ERR_peek_last_error();
    if (err) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        RETURN_STRING(buf);
    }
    RETURN_EMPTY_STRING();
}

PHP_METHOD(Connection, getNegotiatedCipher) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    const SSL_CIPHER *cipher = SSL_get_current_cipher(obj->ssl);
    if (!cipher) {
        RETURN_EMPTY_STRING();
    }
    RETURN_STRING(SSL_CIPHER_get_name(cipher));
}

PHP_METHOD(Connection, getNegotiatedGroup) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    uint16_t group_id = SSL_get_group_id(obj->ssl);
    if (group_id == 0) {
        RETURN_EMPTY_STRING();
    }
    const char *name = SSL_get_group_name(group_id);
    if (!name) {
        RETURN_EMPTY_STRING();
    }
    RETURN_STRING(name);
}

PHP_METHOD(Connection, getNegotiatedAlpn) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    const uint8_t *proto; unsigned proto_len;
    SSL_get0_alpn_selected(obj->ssl, &proto, &proto_len);
    if (proto && proto_len > 0) {
        RETURN_STRINGL((const char *)proto, proto_len);
    }
    RETURN_EMPTY_STRING();
}

PHP_METHOD(Connection, getProtocolVersion) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    RETURN_LONG(SSL_version(obj->ssl));
}

PHP_METHOD(Connection, getEchStatus) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    if (SSL_ech_accepted(obj->ssl)) {
        RETURN_LONG(1); /* ECH_STATUS_SUCCESS */
    }
    const uint8_t *retry;
    size_t retry_len;
    SSL_get0_ech_retry_configs(obj->ssl, &retry, &retry_len);
    if (retry && retry_len > 0) {
        RETURN_LONG(2); /* ECH_STATUS_REJECTED (server sent retry configs) */
    }
    RETURN_LONG(3); /* ECH_STATUS_NOT_NEGOTIATED */
}

PHP_METHOD(Connection, getEchRetryConfigs) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    const uint8_t *retry_configs;
    size_t retry_configs_len;
    SSL_get0_ech_retry_configs(obj->ssl, &retry_configs, &retry_configs_len);

    if (retry_configs && retry_configs_len > 0) {
        RETURN_STRINGL((const char *)retry_configs, retry_configs_len);
    }
    RETURN_EMPTY_STRING();
}

PHP_METHOD(Connection, getPeerApplicationSettings) {
    char *proto;
    size_t proto_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(proto, proto_len)
    ZEND_PARSE_PARAMETERS_END();

    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    if (!SSL_has_application_settings(obj->ssl)) {
        RETURN_EMPTY_STRING();
    }

    const uint8_t *settings;
    size_t settings_len;
    SSL_get0_peer_application_settings(obj->ssl, &settings, &settings_len);

    if (!settings || settings_len == 0) {
        RETURN_EMPTY_STRING();
    }
    RETURN_STRINGL((const char *)settings, settings_len);
}

PHP_METHOD(Connection, getEarlyDataStatus) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    /* Map BoringSSL early data reason to our constants.
     * ssl_early_data_accepted = 0 means it was accepted. */
    enum ssl_early_data_reason_t reason = SSL_get_early_data_reason(obj->ssl);
    if (reason == ssl_early_data_accepted) {
        RETURN_LONG(2); /* EARLY_DATA_ACCEPTED */
    } else if (reason == ssl_early_data_no_session_offered ||
               reason == ssl_early_data_disabled) {
        RETURN_LONG(0); /* EARLY_DATA_NOT_SENT */
    } else {
        RETURN_LONG(1); /* EARLY_DATA_REJECTED */
    }
}

PHP_METHOD(Connection, getSession) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    SSL_SESSION *sess = SSL_get1_session(obj->ssl);
    if (!sess) {
        RETURN_NULL();
    }

    object_init_ex(return_value, bssl_session_ce);
    bssl_session_obj *sobj = Z_BSSL_SESSION_P(return_value);
    sobj->session = sess;
}

PHP_METHOD(Connection, setSession) {
    zval *session_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(session_zv, bssl_session_ce)
    ZEND_PARSE_PARAMETERS_END();

    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);

    bssl_session_obj *sobj = Z_BSSL_SESSION_P(session_zv);
    if (!sobj->session) {
        zend_throw_exception(bssl_exception_ce, "Session is empty", 0);
        RETURN_THROWS();
    }

    if (!SSL_set_session(obj->ssl, sobj->session)) {
        bssl_throw_ssl_error("Failed to set session");
        RETURN_THROWS();
    }

    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Connection, setHostname) {
    char *hostname;
    size_t hostname_len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(hostname, hostname_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    if (!SSL_set_tlsext_host_name(obj->ssl, hostname)) {
        bssl_throw_ssl_error("Failed to set hostname (SNI)");
        RETURN_THROWS();
    }
    /* Enforce certificate hostname verification */
    X509_VERIFY_PARAM *param = SSL_get0_param(obj->ssl);
    if (!X509_VERIFY_PARAM_set1_host(param, hostname, hostname_len)) {
        bssl_throw_ssl_error("Failed to set hostname verification");
        RETURN_THROWS();
    }
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

PHP_METHOD(Connection, getVerifyResult) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    RETURN_LONG(SSL_get_verify_result(obj->ssl));
}

PHP_METHOD(Connection, isSessionReused) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    RETURN_BOOL(SSL_session_reused(obj->ssl));
}

PHP_METHOD(Connection, peek) {
    zend_long length;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    if (length <= 0 || length > INT_MAX) {
        zend_throw_exception(zend_ce_value_error,
            "Peek length must be between 1 and " ZEND_TOSTR(INT_MAX), 0);
        RETURN_THROWS();
    }
    zend_string *buf = zend_string_alloc(length, 0);
    ERR_clear_error();
    int bytes = SSL_peek(obj->ssl, ZSTR_VAL(buf), (int)length);
    if (bytes <= 0) {
        zend_string_release(buf);
        int err = SSL_get_error(obj->ssl, bytes);
        if (err == SSL_ERROR_ZERO_RETURN) { RETURN_FALSE; }
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { RETURN_EMPTY_STRING(); }
        bssl_throw_ssl_error("SSL peek failed");
        RETURN_THROWS();
    }
    ZSTR_LEN(buf) = bytes;
    ZSTR_VAL(buf)[bytes] = '\0';
    RETURN_NEW_STR(buf);
}

PHP_METHOD(Connection, keyUpdate) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    ERR_clear_error();
    if (!SSL_key_update(obj->ssl, SSL_KEY_UPDATE_REQUESTED)) {
        bssl_throw_ssl_error("Failed to initiate key update");
        RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_METHOD(Connection, getOcspResponse) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    const uint8_t *resp;
    size_t resp_len;
    SSL_get0_ocsp_response(obj->ssl, &resp, &resp_len);
    if (resp && resp_len > 0) {
        RETURN_STRINGL((const char *)resp, resp_len);
    }
    RETURN_EMPTY_STRING();
}

PHP_METHOD(Connection, getSignedCertTimestamps) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    const uint8_t *scts;
    size_t scts_len;
    SSL_get0_signed_cert_timestamp_list(obj->ssl, &scts, &scts_len);
    if (scts && scts_len > 0) {
        RETURN_STRINGL((const char *)scts, scts_len);
    }
    RETURN_EMPTY_STRING();
}

PHP_METHOD(Connection, getPeerCertificate) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    X509 *cert = SSL_get_peer_certificate(obj->ssl);
    if (!cert) {
        RETURN_NULL();
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        X509_free(cert);
        bssl_throw_ssl_error("Failed to create BIO");
        RETURN_THROWS();
    }
    if (PEM_write_bio_X509(bio, cert) != 1) {
        BIO_free(bio);
        X509_free(cert);
        bssl_throw_ssl_error("Failed to write certificate to PEM");
        RETURN_THROWS();
    }
    const uint8_t *pem_data;
    size_t pem_len;
    BIO_mem_contents(bio, &pem_data, &pem_len);
    zend_string *result = zend_string_init((const char *)pem_data, pem_len, 0);
    BIO_free(bio);
    X509_free(cert);
    RETURN_NEW_STR(result);
}

PHP_METHOD(Connection, getPeerCertificateChain) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(obj->ssl);
    array_init(return_value);
    if (!chain) { return; }
    for (size_t i = 0; i < sk_X509_num(chain); i++) {
        X509 *cert = sk_X509_value(chain, i);
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio) continue;
        if (PEM_write_bio_X509(bio, cert) == 1) {
            const uint8_t *pem_data;
            size_t pem_len;
            BIO_mem_contents(bio, &pem_data, &pem_len);
            add_next_index_stringl(return_value, (const char *)pem_data, pem_len);
        }
        BIO_free(bio);
    }
}

PHP_METHOD(Connection, exportKeyingMaterial) {
    char *label, *context_val = NULL;
    size_t label_len, context_len = 0;
    zend_long length;
    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_STRING(label, label_len)
        Z_PARAM_LONG(length)
        Z_PARAM_OPTIONAL
        Z_PARAM_STRING_OR_NULL(context_val, context_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    if (length <= 0 || length > INT_MAX) {
        zend_throw_exception(zend_ce_value_error,
            "Length must be between 1 and " ZEND_TOSTR(INT_MAX), 0);
        RETURN_THROWS();
    }
    zend_string *result = zend_string_alloc(length, 0);
    int use_context = (context_val != NULL) ? 1 : 0;
    ERR_clear_error();
    if (SSL_export_keying_material(obj->ssl,
            (uint8_t *)ZSTR_VAL(result), length,
            label, label_len,
            (const uint8_t *)context_val, context_len,
            use_context) != 1) {
        zend_string_release(result);
        bssl_throw_ssl_error("Failed to export keying material");
        RETURN_THROWS();
    }
    ZSTR_VAL(result)[length] = '\0';
    RETURN_NEW_STR(result);
}

PHP_METHOD(Connection, setRenegotiateMode) {
    zend_long mode;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(mode)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(ZEND_THIS);
    BSSL_CONN_CHECK(obj);
    if (mode < ssl_renegotiate_never || mode > ssl_renegotiate_explicit) {
        zend_throw_exception(zend_ce_value_error,
            "Invalid renegotiate mode", 0);
        RETURN_THROWS();
    }
    SSL_set_renegotiate_mode(obj->ssl, (enum ssl_renegotiate_mode_t)mode);
    RETURN_ZVAL(ZEND_THIS, 1, 0);
}

/* --------------------------------------------------------------------------
 * Session methods
 * ------------------------------------------------------------------------ */

PHP_METHOD(Session, fromBytes) {
    char *bytes;
    size_t bytes_len;
    zval *ctx_zv;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(bytes, bytes_len)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce)
    ZEND_PARSE_PARAMETERS_END();

    bssl_ctx_obj *ctx_obj = Z_BSSL_CTX_P(ctx_zv);
    if (!ctx_obj->ctx) {
        zend_throw_exception(bssl_exception_ce,
            "Context not initialized", 0);
        RETURN_THROWS();
    }

    SSL_SESSION *sess = SSL_SESSION_from_bytes(
        (const uint8_t *)bytes, bytes_len, ctx_obj->ctx);
    if (!sess) {
        bssl_throw_ssl_error("Failed to deserialize session");
        RETURN_THROWS();
    }

    object_init_ex(return_value, bssl_session_ce);
    bssl_session_obj *sobj = Z_BSSL_SESSION_P(return_value);
    sobj->session = sess;
}

PHP_METHOD(Session, toBytes) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_session_obj *obj = Z_BSSL_SESSION_P(ZEND_THIS);

    if (!obj->session) {
        zend_throw_exception(bssl_exception_ce, "Session is empty", 0);
        RETURN_THROWS();
    }

    uint8_t *data;
    size_t len;
    if (!SSL_SESSION_to_bytes(obj->session, &data, &len)) {
        bssl_throw_ssl_error("Failed to serialize session");
        RETURN_THROWS();
    }

    zend_string *result = zend_string_init((char *)data, len, 0);
    OPENSSL_free(data);
    RETURN_NEW_STR(result);
}

PHP_METHOD(Session, getId) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_session_obj *obj = Z_BSSL_SESSION_P(ZEND_THIS);

    if (!obj->session) {
        RETURN_EMPTY_STRING();
    }

    unsigned id_len;
    const uint8_t *id = SSL_SESSION_get_id(obj->session, &id_len);
    RETURN_STRINGL((const char *)id, id_len);
}

PHP_METHOD(Session, getTimeout) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_session_obj *obj = Z_BSSL_SESSION_P(ZEND_THIS);

    if (!obj->session) {
        RETURN_LONG(0);
    }

    RETURN_LONG(SSL_SESSION_get_timeout(obj->session));
}

PHP_METHOD(Session, hasTicket) {
    ZEND_PARSE_PARAMETERS_NONE();
    bssl_session_obj *obj = Z_BSSL_SESSION_P(ZEND_THIS);

    if (!obj->session) {
        RETURN_FALSE;
    }

    RETURN_BOOL(SSL_SESSION_has_ticket(obj->session));
}

/* --------------------------------------------------------------------------
 * Procedural function API
 * ------------------------------------------------------------------------ */

/* -- Arginfo for procedural functions -- */

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_ctx, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, context, BoringSSL\\Context, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_ctx_string, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, context, BoringSSL\\Context, 0)
    ZEND_ARG_TYPE_INFO(0, value, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_ctx_array, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, context, BoringSSL\\Context, 0)
    ZEND_ARG_TYPE_INFO(0, value, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_ctx_bool, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, context, BoringSSL\\Context, 0)
    ZEND_ARG_TYPE_INFO(0, enabled, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_ctx_long, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, context, BoringSSL\\Context, 0)
    ZEND_ARG_TYPE_INFO(0, value, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_ctx_app_settings, 0, 0, 3)
    ZEND_ARG_OBJ_INFO(0, context, BoringSSL\\Context, 0)
    ZEND_ARG_TYPE_INFO(0, proto, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, settings, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_ctx_load_verify, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, context, BoringSSL\\Context, 0)
    ZEND_ARG_TYPE_INFO(0, caFile, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, caPath, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_ctx_set_verify, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, context, BoringSSL\\Context, 0)
    ZEND_ARG_TYPE_INFO(0, mode, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_conn, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\Connection, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_conn_stream, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\Connection, 0)
    ZEND_ARG_INFO(0, stream)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_conn_fd, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\Connection, 0)
    ZEND_ARG_TYPE_INFO(0, fd, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_conn_read, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\Connection, 0)
    ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_conn_write, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\Connection, 0)
    ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_conn_session, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\Connection, 0)
    ZEND_ARG_OBJ_INFO(0, session, BoringSSL\\Session, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_conn_proto, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\Connection, 0)
    ZEND_ARG_TYPE_INFO(0, proto, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_session_from_bytes, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, bytes, IS_STRING, 0)
    ZEND_ARG_OBJ_INFO(0, context, BoringSSL\\Context, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_session, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, session, BoringSSL\\Session, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_conn_hostname, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\Connection, 0)
    ZEND_ARG_TYPE_INFO(0, hostname, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_conn_long, 0, 0, 2)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\Connection, 0)
    ZEND_ARG_TYPE_INFO(0, value, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_fn_conn_export_km, 0, 0, 3)
    ZEND_ARG_OBJ_INFO(0, connection, BoringSSL\\Connection, 0)
    ZEND_ARG_TYPE_INFO(0, label, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, context, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

/* -- Helper: call a method on an object from a procedural function -- */
#define BSSL_CALL_METHOD(ce, obj_zv, method_name, retval, param_count, params) \
    do { \
        zval _fn; \
        ZVAL_STRING(&_fn, method_name); \
        call_user_function(NULL, obj_zv, &_fn, retval, param_count, params); \
        zval_ptr_dtor(&_fn); \
    } while (0)

/* -- Context functions -- */

PHP_FUNCTION(boringssl_context_new) {
    ZEND_PARSE_PARAMETERS_NONE();
    object_init_ex(return_value, bssl_ctx_ce);
    zval rv;
    BSSL_CALL_METHOD(bssl_ctx_ce, return_value, "new", &rv, 0, NULL);
    zval_ptr_dtor(&rv);
    if (EG(exception)) {
        zval_ptr_dtor(return_value);
        ZVAL_NULL(return_value);
        return;
    }
}

PHP_FUNCTION(boringssl_context_new_server) {
    ZEND_PARSE_PARAMETERS_NONE();
    object_init_ex(return_value, bssl_ctx_ce);
    zval rv;
    BSSL_CALL_METHOD(bssl_ctx_ce, return_value, "newServer", &rv, 0, NULL);
    zval_ptr_dtor(&rv);
    if (EG(exception)) {
        zval_ptr_dtor(return_value);
        ZVAL_NULL(return_value);
        return;
    }
}

PHP_FUNCTION(boringssl_context_set_cipher_list) {
    zval *ctx_zv; char *str; size_t str_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce)
        Z_PARAM_STRING(str, str_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (SSL_CTX_set_cipher_list(obj->ctx, str) != 1) {
        bssl_throw_ssl_error("Failed to set cipher list"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_groups_list) {
    zval *ctx_zv; char *str; size_t str_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce)
        Z_PARAM_STRING(str, str_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (SSL_CTX_set1_groups_list(obj->ctx, str) != 1) {
        bssl_throw_ssl_error("Failed to set supported groups"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_verify_algorithm_prefs) {
    zval *ctx_zv, *alg_ids;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce)
        Z_PARAM_ARRAY(alg_ids)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    HashTable *ht = Z_ARRVAL_P(alg_ids);
    uint32_t count = zend_hash_num_elements(ht);
    if (count == 0) { zend_throw_exception(zend_ce_value_error, "Array must not be empty", 0); RETURN_THROWS(); }
    uint16_t *prefs = ecalloc(count, sizeof(uint16_t));
    uint32_t i = 0; zval *entry;
    ZEND_HASH_FOREACH_VAL(ht, entry) {
        zend_long val = zval_get_long(entry);
        if (val < 0 || val > 0xFFFF) {
            efree(prefs);
            zend_throw_exception_ex(zend_ce_value_error, 0,
                "Algorithm ID must be between 0 and 65535, got " ZEND_LONG_FMT, val);
            RETURN_THROWS();
        }
        prefs[i++] = (uint16_t)val;
    } ZEND_HASH_FOREACH_END();
    int ok = SSL_CTX_set_verify_algorithm_prefs(obj->ctx, prefs, count);
    efree(prefs);
    if (!ok) { bssl_throw_ssl_error("Failed to set verify algorithm preferences"); RETURN_THROWS(); }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_signing_algorithm_prefs) {
    zval *ctx_zv, *alg_ids;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce)
        Z_PARAM_ARRAY(alg_ids)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    HashTable *ht = Z_ARRVAL_P(alg_ids);
    uint32_t count = zend_hash_num_elements(ht);
    if (count == 0) { zend_throw_exception(zend_ce_value_error, "Array must not be empty", 0); RETURN_THROWS(); }
    uint16_t *prefs = ecalloc(count, sizeof(uint16_t));
    uint32_t i = 0; zval *entry;
    ZEND_HASH_FOREACH_VAL(ht, entry) {
        zend_long val = zval_get_long(entry);
        if (val < 0 || val > 0xFFFF) {
            efree(prefs);
            zend_throw_exception_ex(zend_ce_value_error, 0,
                "Algorithm ID must be between 0 and 65535, got " ZEND_LONG_FMT, val);
            RETURN_THROWS();
        }
        prefs[i++] = (uint16_t)val;
    } ZEND_HASH_FOREACH_END();
    int ok = SSL_CTX_set_signing_algorithm_prefs(obj->ctx, prefs, count);
    efree(prefs);
    if (!ok) { bssl_throw_ssl_error("Failed to set signing algorithm preferences"); RETURN_THROWS(); }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_alpn_protos) {
    zval *ctx_zv, *protocols;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_ARRAY(protocols)
    ZEND_PARSE_PARAMETERS_END();
    zval params[1]; ZVAL_COPY_VALUE(&params[0], protocols);
    BSSL_CALL_METHOD(bssl_ctx_ce, ctx_zv, "setAlpnProtos", return_value, 1, params);
    if (EG(exception)) { return; }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_get_alpn_proto) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    const uint8_t *proto; unsigned proto_len;
    SSL_get0_alpn_selected(obj->ssl, &proto, &proto_len);
    if (proto && proto_len > 0) {
        RETURN_STRINGL((const char *)proto, proto_len);
    }
    RETURN_EMPTY_STRING();
}

PHP_FUNCTION(boringssl_context_set_grease) {
    zval *ctx_zv; zend_bool enabled;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_BOOL(enabled)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    SSL_CTX_set_grease_enabled(obj->ctx, enabled ? 1 : 0);
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_permute_extensions) {
    zval *ctx_zv; zend_bool enabled;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_BOOL(enabled)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    SSL_CTX_set_permute_extensions(obj->ctx, enabled ? 1 : 0);
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_add_application_settings) {
    zval *ctx_zv; char *proto, *settings; size_t proto_len, settings_len;
    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce)
        Z_PARAM_STRING(proto, proto_len) Z_PARAM_STRING(settings, settings_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    bssl_alps_entry *entry = ecalloc(1, sizeof(bssl_alps_entry));
    entry->proto = estrndup(proto, proto_len); entry->proto_len = proto_len;
    entry->settings = estrndup(settings, settings_len); entry->settings_len = settings_len;
    entry->next = obj->alps_entries; obj->alps_entries = entry;
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_alps_use_new_codepoint) {
    zval *ctx_zv; zend_bool use_new;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_BOOL(use_new)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    obj->alps_use_new_codepoint = use_new;
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_add_cert_compression_alg) {
    zval *ctx_zv; zend_long alg_id;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_LONG(alg_id)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    int ok = 0;
    switch (alg_id) {
#ifdef HAVE_BROTLI
        case 2: ok = SSL_CTX_add_cert_compression_alg(obj->ctx, 2, bssl_cert_compress_brotli, bssl_cert_decompress_brotli); break;
#endif
#ifdef HAVE_ZLIB
        case 1: ok = SSL_CTX_add_cert_compression_alg(obj->ctx, 1, bssl_cert_compress_zlib, bssl_cert_decompress_zlib); break;
#endif
#ifdef HAVE_ZSTD
        case 3: ok = SSL_CTX_add_cert_compression_alg(obj->ctx, 3, bssl_cert_compress_zstd, bssl_cert_decompress_zstd); break;
#endif
        default:
            zend_throw_exception_ex(zend_ce_value_error, 0, "Unsupported cert compression algorithm: " ZEND_LONG_FMT, alg_id);
            RETURN_THROWS();
    }
    if (!ok) { bssl_throw_ssl_error("Failed to add cert compression algorithm"); RETURN_THROWS(); }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_ech_config_list) {
    zval *ctx_zv; char *ech; size_t ech_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_STRING(ech, ech_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (obj->ech_config) efree(obj->ech_config);
    obj->ech_config = estrndup(ech, ech_len); obj->ech_config_len = ech_len;
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_min_proto_version) {
    zval *ctx_zv; zend_long ver;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_LONG(ver)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (ver < 0 || ver > 0xFFFF) {
        zend_throw_exception(zend_ce_value_error, "Protocol version must be between 0 and 65535", 0);
        RETURN_THROWS();
    }
    if (!SSL_CTX_set_min_proto_version(obj->ctx, (uint16_t)ver)) {
        bssl_throw_ssl_error("Failed to set min proto version"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_max_proto_version) {
    zval *ctx_zv; zend_long ver;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_LONG(ver)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (ver < 0 || ver > 0xFFFF) {
        zend_throw_exception(zend_ce_value_error, "Protocol version must be between 0 and 65535", 0);
        RETURN_THROWS();
    }
    if (!SSL_CTX_set_max_proto_version(obj->ctx, (uint16_t)ver)) {
        bssl_throw_ssl_error("Failed to set max proto version"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_early_data) {
    zval *ctx_zv; zend_bool enabled;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_BOOL(enabled)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    SSL_CTX_set_early_data_enabled(obj->ctx, enabled ? 1 : 0);
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_use_certificate_file) {
    zval *ctx_zv; char *path; size_t path_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (php_check_open_basedir(path)) { RETURN_THROWS(); }
    if (SSL_CTX_use_certificate_file(obj->ctx, path, SSL_FILETYPE_PEM) != 1) {
        bssl_throw_ssl_error("Failed to load certificate file"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_use_private_key_file) {
    zval *ctx_zv; char *path; size_t path_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (php_check_open_basedir(path)) { RETURN_THROWS(); }
    if (SSL_CTX_use_PrivateKey_file(obj->ctx, path, SSL_FILETYPE_PEM) != 1) {
        bssl_throw_ssl_error("Failed to load private key file"); RETURN_THROWS();
    }
    if (SSL_CTX_check_private_key(obj->ctx) != 1) {
        bssl_throw_ssl_error("Private key does not match certificate"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_load_verify_locations) {
    zval *ctx_zv; char *ca_file; size_t ca_file_len;
    char *ca_path = NULL; size_t ca_path_len = 0;
    ZEND_PARSE_PARAMETERS_START(2, 3)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce)
        Z_PARAM_STRING(ca_file, ca_file_len)
        Z_PARAM_OPTIONAL Z_PARAM_STRING_OR_NULL(ca_path, ca_path_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (php_check_open_basedir(ca_file)) { RETURN_THROWS(); }
    if (ca_path && php_check_open_basedir(ca_path)) { RETURN_THROWS(); }
    if (SSL_CTX_load_verify_locations(obj->ctx, ca_file, ca_path_len > 0 ? ca_path : NULL) != 1) {
        bssl_throw_ssl_error("Failed to load verify locations"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_verify) {
    zval *ctx_zv; zend_long mode;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_LONG(mode)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    SSL_CTX_set_verify(obj->ctx, (int)mode, NULL);
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_default_verify_paths) {
    zval *ctx_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (!SSL_CTX_set_default_verify_paths(obj->ctx)) {
        bssl_throw_ssl_error("Failed to set default verify paths"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_verify_depth) {
    zval *ctx_zv; zend_long depth;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_LONG(depth)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (depth < 0 || depth > 100) {
        zend_throw_exception(zend_ce_value_error, "Verify depth must be between 0 and 100", 0);
        RETURN_THROWS();
    }
    SSL_CTX_set_verify_depth(obj->ctx, (int)depth);
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_options) {
    zval *ctx_zv; zend_long options;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_LONG(options)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (options < 0 || options > UINT32_MAX) {
        zend_throw_exception(zend_ce_value_error, "Options must be a valid 32-bit unsigned value", 0);
        RETURN_THROWS();
    }
    SSL_CTX_set_options(obj->ctx, (uint32_t)options);
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_clear_options) {
    zval *ctx_zv; zend_long options;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_LONG(options)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (options < 0 || options > UINT32_MAX) {
        zend_throw_exception(zend_ce_value_error, "Options must be a valid 32-bit unsigned value", 0);
        RETURN_THROWS();
    }
    SSL_CTX_clear_options(obj->ctx, (uint32_t)options);
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_get_options) {
    zval *ctx_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    RETURN_LONG((zend_long)SSL_CTX_get_options(obj->ctx));
}

PHP_FUNCTION(boringssl_context_enable_ocsp_stapling) {
    zval *ctx_zv; zend_bool enabled;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_BOOL(enabled)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (enabled) { SSL_CTX_enable_ocsp_stapling(obj->ctx); }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_enable_signed_cert_timestamps) {
    zval *ctx_zv; zend_bool enabled;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_BOOL(enabled)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (enabled) { SSL_CTX_enable_signed_cert_timestamps(obj->ctx); }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_keylog_file) {
    zval *ctx_zv; char *path; size_t path_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END();
    zval params[1];
    ZVAL_STRINGL(&params[0], path, path_len);
    BSSL_CALL_METHOD(bssl_ctx_ce, ctx_zv, "setKeylogFile", return_value, 1, params);
    zval_ptr_dtor(&params[0]);
    if (EG(exception)) { return; }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_load_client_ca_file) {
    zval *ctx_zv; char *path; size_t path_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_STRING(path, path_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (php_check_open_basedir(path)) { RETURN_THROWS(); }
    STACK_OF(X509_NAME) *ca_list = SSL_load_client_CA_file(path);
    if (!ca_list) { bssl_throw_ssl_error("Failed to load client CA file"); RETURN_THROWS(); }
    SSL_CTX_set_client_CA_list(obj->ctx, ca_list);
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_set_session_ticket_keys) {
    zval *ctx_zv; char *keys; size_t keys_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_STRING(keys, keys_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *obj = Z_BSSL_CTX_P(ctx_zv); BSSL_CTX_CHECK(obj);
    if (keys_len != 48) {
        zend_throw_exception(zend_ce_value_error, "Session ticket keys must be exactly 48 bytes", 0);
        RETURN_THROWS();
    }
    if (!SSL_CTX_set_tlsext_ticket_keys(obj->ctx, keys, 48)) {
        bssl_throw_ssl_error("Failed to set session ticket keys"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_use_certificate_chain_pem) {
    zval *ctx_zv; char *pem; size_t pem_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_STRING(pem, pem_len)
    ZEND_PARSE_PARAMETERS_END();
    zval params[1];
    ZVAL_STRINGL(&params[0], pem, pem_len);
    BSSL_CALL_METHOD(bssl_ctx_ce, ctx_zv, "useCertificateChainPem", return_value, 1, params);
    zval_ptr_dtor(&params[0]);
    if (EG(exception)) { return; }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_context_use_private_key_pem) {
    zval *ctx_zv; char *pem; size_t pem_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce) Z_PARAM_STRING(pem, pem_len)
    ZEND_PARSE_PARAMETERS_END();
    zval params[1];
    ZVAL_STRINGL(&params[0], pem, pem_len);
    BSSL_CALL_METHOD(bssl_ctx_ce, ctx_zv, "usePrivateKeyPem", return_value, 1, params);
    zval_ptr_dtor(&params[0]);
    if (EG(exception)) { return; }
    RETURN_TRUE;
}

/* -- Connection functions -- */

PHP_FUNCTION(boringssl_new_connection) {
    zval *ctx_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce)
    ZEND_PARSE_PARAMETERS_END();
    BSSL_CALL_METHOD(bssl_ctx_ce, ctx_zv, "newConnection", return_value, 0, NULL);
}

PHP_FUNCTION(boringssl_set_fd) {
    zval *conn_zv; zend_long fd;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce) Z_PARAM_LONG(fd)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    if (fd < 0 || fd > INT_MAX) {
        zend_throw_exception(zend_ce_value_error, "Invalid file descriptor", 0); RETURN_THROWS();
    }
    if (!SSL_set_fd(obj->ssl, (int)fd)) {
        bssl_throw_ssl_error("Failed to set file descriptor"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_set_stream) {
    zval *conn_zv, *zstream;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce) Z_PARAM_ZVAL(zstream)
    ZEND_PARSE_PARAMETERS_END();
    zval params[1]; ZVAL_COPY_VALUE(&params[0], zstream);
    BSSL_CALL_METHOD(bssl_conn_ce, conn_zv, "setStream", return_value, 1, params);
    if (EG(exception)) { return; }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_connect) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    ERR_clear_error();
    int ret = SSL_connect(obj->ssl);
    if (ret != 1) {
        int err = SSL_get_error(obj->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { RETURN_FALSE; }
        bssl_throw_ssl_error("SSL handshake failed"); RETURN_THROWS();
    }
    obj->ssl_active = 1;
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_accept) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    ERR_clear_error();
    int ret = SSL_accept(obj->ssl);
    if (ret != 1) {
        int err = SSL_get_error(obj->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { RETURN_FALSE; }
        bssl_throw_ssl_error("SSL accept failed"); RETURN_THROWS();
    }
    obj->ssl_active = 1;
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_read) {
    zval *conn_zv; zend_long length;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce) Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    if (length <= 0 || length > INT_MAX) {
        zend_throw_exception(zend_ce_value_error,
            "Read length must be between 1 and " ZEND_TOSTR(INT_MAX), 0);
        RETURN_THROWS();
    }
    zend_string *buf = zend_string_alloc(length, 0);
    ERR_clear_error();
    int bytes = SSL_read(obj->ssl, ZSTR_VAL(buf), (int)length);
    if (bytes <= 0) {
        zend_string_release(buf);
        int err = SSL_get_error(obj->ssl, bytes);
        if (err == SSL_ERROR_ZERO_RETURN) { RETURN_FALSE; }
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { RETURN_EMPTY_STRING(); }
        bssl_throw_ssl_error("SSL read failed"); RETURN_THROWS();
    }
    ZSTR_LEN(buf) = bytes; ZSTR_VAL(buf)[bytes] = '\0';
    RETURN_NEW_STR(buf);
}

PHP_FUNCTION(boringssl_write) {
    zval *conn_zv; char *data; size_t data_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce) Z_PARAM_STRING(data, data_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    if (data_len > INT_MAX) {
        zend_throw_exception(zend_ce_value_error,
            "Data too large for single SSL_write", 0);
        RETURN_THROWS();
    }
    ERR_clear_error();
    int bytes = SSL_write(obj->ssl, data, (int)data_len);
    if (bytes <= 0) {
        int err = SSL_get_error(obj->ssl, bytes);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) { RETURN_LONG(0); }
        bssl_throw_ssl_error("SSL write failed"); RETURN_THROWS();
    }
    RETURN_LONG(bytes);
}

PHP_FUNCTION(boringssl_pending) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    RETURN_LONG(SSL_pending(obj->ssl));
}

PHP_FUNCTION(boringssl_shutdown) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    int ret = SSL_shutdown(obj->ssl);
    if (ret < 0) { bssl_throw_ssl_error("SSL shutdown failed"); RETURN_THROWS(); }
    obj->ssl_active = 0;
    RETURN_BOOL(ret == 1);
}

PHP_FUNCTION(boringssl_get_cipher) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    const SSL_CIPHER *c = SSL_get_current_cipher(obj->ssl);
    if (!c) { RETURN_EMPTY_STRING(); }
    RETURN_STRING(SSL_CIPHER_get_name(c));
}

PHP_FUNCTION(boringssl_get_group) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    uint16_t gid = SSL_get_group_id(obj->ssl);
    if (gid == 0) { RETURN_EMPTY_STRING(); }
    const char *name = SSL_get_group_name(gid);
    RETURN_STRING(name ? name : "");
}

PHP_FUNCTION(boringssl_get_version) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    RETURN_LONG(SSL_version(obj->ssl));
}

PHP_FUNCTION(boringssl_get_session) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    SSL_SESSION *sess = SSL_get1_session(obj->ssl);
    if (!sess) { RETURN_NULL(); }
    object_init_ex(return_value, bssl_session_ce);
    bssl_session_obj *sobj = Z_BSSL_SESSION_P(return_value);
    sobj->session = sess;
}

PHP_FUNCTION(boringssl_set_session) {
    zval *conn_zv, *session_zv;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
        Z_PARAM_OBJECT_OF_CLASS(session_zv, bssl_session_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    bssl_session_obj *sobj = Z_BSSL_SESSION_P(session_zv);
    if (!sobj->session) { zend_throw_exception(bssl_exception_ce, "Session is empty", 0); RETURN_THROWS(); }
    if (!SSL_set_session(obj->ssl, sobj->session)) {
        bssl_throw_ssl_error("Failed to set session"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_set_hostname) {
    zval *conn_zv; char *hostname; size_t hostname_len;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce) Z_PARAM_STRING(hostname, hostname_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    if (!SSL_set_tlsext_host_name(obj->ssl, hostname)) {
        bssl_throw_ssl_error("Failed to set hostname (SNI)"); RETURN_THROWS();
    }
    /* Enforce certificate hostname verification */
    X509_VERIFY_PARAM *param = SSL_get0_param(obj->ssl);
    if (!X509_VERIFY_PARAM_set1_host(param, hostname, hostname_len)) {
        bssl_throw_ssl_error("Failed to set hostname verification"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_get_verify_result) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    RETURN_LONG(SSL_get_verify_result(obj->ssl));
}

PHP_FUNCTION(boringssl_session_reused) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    RETURN_BOOL(SSL_session_reused(obj->ssl));
}

PHP_FUNCTION(boringssl_peek) {
    zval *conn_zv; zend_long length;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce) Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    if (length <= 0 || length > INT_MAX) {
        zend_throw_exception(zend_ce_value_error, "Peek length must be between 1 and " ZEND_TOSTR(INT_MAX), 0);
        RETURN_THROWS();
    }
    zend_string *buf = zend_string_alloc(length, 0);
    ERR_clear_error();
    int bytes = SSL_peek(obj->ssl, ZSTR_VAL(buf), (int)length);
    if (bytes <= 0) {
        zend_string_release(buf);
        int err = SSL_get_error(obj->ssl, bytes);
        if (err == SSL_ERROR_ZERO_RETURN) { RETURN_FALSE; }
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { RETURN_EMPTY_STRING(); }
        bssl_throw_ssl_error("SSL peek failed"); RETURN_THROWS();
    }
    ZSTR_LEN(buf) = bytes; ZSTR_VAL(buf)[bytes] = '\0';
    RETURN_NEW_STR(buf);
}

PHP_FUNCTION(boringssl_key_update) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    ERR_clear_error();
    if (!SSL_key_update(obj->ssl, SSL_KEY_UPDATE_REQUESTED)) {
        bssl_throw_ssl_error("Failed to initiate key update"); RETURN_THROWS();
    }
    RETURN_TRUE;
}

PHP_FUNCTION(boringssl_get_ocsp_response) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    const uint8_t *resp; size_t resp_len;
    SSL_get0_ocsp_response(obj->ssl, &resp, &resp_len);
    if (resp && resp_len > 0) { RETURN_STRINGL((const char *)resp, resp_len); }
    RETURN_EMPTY_STRING();
}

PHP_FUNCTION(boringssl_get_signed_cert_timestamps) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    const uint8_t *scts; size_t scts_len;
    SSL_get0_signed_cert_timestamp_list(obj->ssl, &scts, &scts_len);
    if (scts && scts_len > 0) { RETURN_STRINGL((const char *)scts, scts_len); }
    RETURN_EMPTY_STRING();
}

PHP_FUNCTION(boringssl_get_peer_certificate) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    BSSL_CALL_METHOD(bssl_conn_ce, conn_zv, "getPeerCertificate", return_value, 0, NULL);
}

PHP_FUNCTION(boringssl_get_peer_certificate_chain) {
    zval *conn_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
    ZEND_PARSE_PARAMETERS_END();
    BSSL_CALL_METHOD(bssl_conn_ce, conn_zv, "getPeerCertificateChain", return_value, 0, NULL);
}

PHP_FUNCTION(boringssl_export_keying_material) {
    zval *conn_zv; char *label; size_t label_len; zend_long length;
    char *context_val = NULL; size_t context_len = 0;
    ZEND_PARSE_PARAMETERS_START(3, 4)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce)
        Z_PARAM_STRING(label, label_len)
        Z_PARAM_LONG(length)
        Z_PARAM_OPTIONAL Z_PARAM_STRING_OR_NULL(context_val, context_len)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    if (length <= 0 || length > INT_MAX) {
        zend_throw_exception(zend_ce_value_error, "Length must be between 1 and " ZEND_TOSTR(INT_MAX), 0);
        RETURN_THROWS();
    }
    zend_string *result = zend_string_alloc(length, 0);
    int use_context = (context_val != NULL) ? 1 : 0;
    ERR_clear_error();
    if (SSL_export_keying_material(obj->ssl, (uint8_t *)ZSTR_VAL(result), length,
            label, label_len, (const uint8_t *)context_val, context_len, use_context) != 1) {
        zend_string_release(result);
        bssl_throw_ssl_error("Failed to export keying material"); RETURN_THROWS();
    }
    ZSTR_VAL(result)[length] = '\0';
    RETURN_NEW_STR(result);
}

PHP_FUNCTION(boringssl_set_renegotiate_mode) {
    zval *conn_zv; zend_long mode;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_OBJECT_OF_CLASS(conn_zv, bssl_conn_ce) Z_PARAM_LONG(mode)
    ZEND_PARSE_PARAMETERS_END();
    bssl_conn_obj *obj = Z_BSSL_CONN_P(conn_zv); BSSL_CONN_CHECK(obj);
    if (mode < ssl_renegotiate_never || mode > ssl_renegotiate_explicit) {
        zend_throw_exception(zend_ce_value_error, "Invalid renegotiate mode", 0);
        RETURN_THROWS();
    }
    SSL_set_renegotiate_mode(obj->ssl, (enum ssl_renegotiate_mode_t)mode);
    RETURN_TRUE;
}

/* -- Session functions -- */

PHP_FUNCTION(boringssl_session_from_bytes) {
    char *bytes; size_t bytes_len; zval *ctx_zv;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(bytes, bytes_len)
        Z_PARAM_OBJECT_OF_CLASS(ctx_zv, bssl_ctx_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_ctx_obj *ctx_obj = Z_BSSL_CTX_P(ctx_zv);
    if (!ctx_obj->ctx) { zend_throw_exception(bssl_exception_ce, "Context not initialized", 0); RETURN_THROWS(); }
    SSL_SESSION *sess = SSL_SESSION_from_bytes((const uint8_t *)bytes, bytes_len, ctx_obj->ctx);
    if (!sess) { bssl_throw_ssl_error("Failed to deserialize session"); RETURN_THROWS(); }
    object_init_ex(return_value, bssl_session_ce);
    bssl_session_obj *sobj = Z_BSSL_SESSION_P(return_value);
    sobj->session = sess;
}

PHP_FUNCTION(boringssl_session_to_bytes) {
    zval *session_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(session_zv, bssl_session_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_session_obj *obj = Z_BSSL_SESSION_P(session_zv);
    if (!obj->session) { zend_throw_exception(bssl_exception_ce, "Session is empty", 0); RETURN_THROWS(); }
    uint8_t *data; size_t len;
    if (!SSL_SESSION_to_bytes(obj->session, &data, &len)) {
        bssl_throw_ssl_error("Failed to serialize session"); RETURN_THROWS();
    }
    zend_string *result = zend_string_init((char *)data, len, 0);
    OPENSSL_free(data);
    RETURN_NEW_STR(result);
}

PHP_FUNCTION(boringssl_session_get_id) {
    zval *session_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(session_zv, bssl_session_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_session_obj *obj = Z_BSSL_SESSION_P(session_zv);
    if (!obj->session) { RETURN_EMPTY_STRING(); }
    unsigned id_len;
    const uint8_t *id = SSL_SESSION_get_id(obj->session, &id_len);
    RETURN_STRINGL((const char *)id, id_len);
}

PHP_FUNCTION(boringssl_session_get_timeout) {
    zval *session_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(session_zv, bssl_session_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_session_obj *obj = Z_BSSL_SESSION_P(session_zv);
    if (!obj->session) { RETURN_LONG(0); }
    RETURN_LONG(SSL_SESSION_get_timeout(obj->session));
}

PHP_FUNCTION(boringssl_session_has_ticket) {
    zval *session_zv;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(session_zv, bssl_session_ce)
    ZEND_PARSE_PARAMETERS_END();
    bssl_session_obj *obj = Z_BSSL_SESSION_P(session_zv);
    if (!obj->session) { RETURN_FALSE; }
    RETURN_BOOL(SSL_SESSION_has_ticket(obj->session));
}

/* --------------------------------------------------------------------------
 * Method tables
 * ------------------------------------------------------------------------ */

static const zend_function_entry bssl_ctx_methods[] = {
    PHP_ME(Context, new,                     arginfo_ctx_void,                ZEND_ACC_PUBLIC)
    PHP_ME(Context, newServer,               arginfo_ctx_void,                ZEND_ACC_PUBLIC)
    PHP_ME(Context, setCipherList,            arginfo_ctx_set_cipher_list,     ZEND_ACC_PUBLIC)
    PHP_ME(Context, setCipherSuites,          arginfo_ctx_set_cipher_suites,   ZEND_ACC_PUBLIC)
    PHP_ME(Context, setAlpnProtos,            arginfo_ctx_set_alpn,            ZEND_ACC_PUBLIC)
    PHP_ME(Context, setGroupsList,            arginfo_ctx_set_groups_list,     ZEND_ACC_PUBLIC)
    PHP_ME(Context, setVerifyAlgorithmPrefs,  arginfo_ctx_set_sigalgs,         ZEND_ACC_PUBLIC)
    PHP_ME(Context, setSigningAlgorithmPrefs, arginfo_ctx_set_sigalgs,         ZEND_ACC_PUBLIC)
    PHP_ME(Context, setGreaseEnabled,         arginfo_ctx_set_bool,            ZEND_ACC_PUBLIC)
    PHP_ME(Context, setPermuteExtensions,     arginfo_ctx_set_bool,            ZEND_ACC_PUBLIC)
    PHP_ME(Context, addApplicationSettings,   arginfo_ctx_add_app_settings,    ZEND_ACC_PUBLIC)
    PHP_ME(Context, setAlpsUseNewCodepoint,   arginfo_ctx_set_bool,            ZEND_ACC_PUBLIC)
    PHP_ME(Context, addCertCompressionAlg,    arginfo_ctx_add_cert_compression, ZEND_ACC_PUBLIC)
    PHP_ME(Context, setEchConfigList,         arginfo_ctx_set_ech,             ZEND_ACC_PUBLIC)
    PHP_ME(Context, setMinProtoVersion,       arginfo_ctx_set_proto_version,   ZEND_ACC_PUBLIC)
    PHP_ME(Context, setMaxProtoVersion,       arginfo_ctx_set_proto_version,   ZEND_ACC_PUBLIC)
    PHP_ME(Context, setEarlyDataEnabled,      arginfo_ctx_set_bool,            ZEND_ACC_PUBLIC)
    PHP_ME(Context, useCertificateFile,       arginfo_ctx_use_cert_file,       ZEND_ACC_PUBLIC)
    PHP_ME(Context, useCertificateChainFile,  arginfo_ctx_use_cert_file,       ZEND_ACC_PUBLIC)
    PHP_ME(Context, usePrivateKeyFile,        arginfo_ctx_use_cert_file,       ZEND_ACC_PUBLIC)
    PHP_ME(Context, loadVerifyLocations,      arginfo_ctx_load_verify,         ZEND_ACC_PUBLIC)
    PHP_ME(Context, setVerify,                arginfo_ctx_set_verify,          ZEND_ACC_PUBLIC)
    PHP_ME(Context, setSessionCacheMode,      arginfo_ctx_set_session_cache_mode, ZEND_ACC_PUBLIC)
    PHP_ME(Context, setDefaultVerifyPaths,      arginfo_ctx_void,              ZEND_ACC_PUBLIC)
    PHP_ME(Context, setVerifyDepth,             arginfo_ctx_set_proto_version, ZEND_ACC_PUBLIC)
    PHP_ME(Context, setOptions,                 arginfo_ctx_set_proto_version, ZEND_ACC_PUBLIC)
    PHP_ME(Context, clearOptions,               arginfo_ctx_set_proto_version, ZEND_ACC_PUBLIC)
    PHP_ME(Context, getOptions,                 arginfo_ctx_void,              ZEND_ACC_PUBLIC)
    PHP_ME(Context, enableOcspStapling,         arginfo_ctx_set_bool,          ZEND_ACC_PUBLIC)
    PHP_ME(Context, enableSignedCertTimestamps, arginfo_ctx_set_bool,          ZEND_ACC_PUBLIC)
    PHP_ME(Context, setKeylogFile,              arginfo_ctx_use_cert_file,     ZEND_ACC_PUBLIC)
    PHP_ME(Context, loadClientCAFile,           arginfo_ctx_use_cert_file,     ZEND_ACC_PUBLIC)
    PHP_ME(Context, setSessionTicketKeys,       arginfo_ctx_set_pem_string,    ZEND_ACC_PUBLIC)
    PHP_ME(Context, useCertificateChainPem,     arginfo_ctx_set_pem_string,    ZEND_ACC_PUBLIC)
    PHP_ME(Context, usePrivateKeyPem,           arginfo_ctx_set_pem_string,    ZEND_ACC_PUBLIC)
    PHP_ME(Context, newConnection,            arginfo_ctx_void,                ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry bssl_conn_methods[] = {
    PHP_ME(Connection, setFd,                    arginfo_conn_set_fd,                 ZEND_ACC_PUBLIC)
    PHP_ME(Connection, setStream,                arginfo_conn_set_stream,             ZEND_ACC_PUBLIC)
    PHP_ME(Connection, connect,                  arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, accept,                   arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, read,                     arginfo_conn_read,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, write,                    arginfo_conn_write,                  ZEND_ACC_PUBLIC)
    PHP_ME(Connection, writeEarlyData,           arginfo_conn_write,                  ZEND_ACC_PUBLIC)
    PHP_ME(Connection, pending,                  arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, shutdown,                 arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getError,                 arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getErrorString,           arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getNegotiatedCipher,      arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getNegotiatedAlpn,        arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getNegotiatedGroup,       arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getProtocolVersion,       arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getEchStatus,             arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getEchRetryConfigs,       arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getPeerApplicationSettings, arginfo_conn_get_peer_app_settings, ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getEarlyDataStatus,       arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getSession,               arginfo_conn_void,                   ZEND_ACC_PUBLIC)
    PHP_ME(Connection, setSession,               arginfo_conn_set_session,            ZEND_ACC_PUBLIC)
    PHP_ME(Connection, setHostname,             arginfo_conn_set_hostname,              ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getVerifyResult,         arginfo_conn_void,                      ZEND_ACC_PUBLIC)
    PHP_ME(Connection, isSessionReused,         arginfo_conn_void,                      ZEND_ACC_PUBLIC)
    PHP_ME(Connection, peek,                    arginfo_conn_read,                      ZEND_ACC_PUBLIC)
    PHP_ME(Connection, keyUpdate,               arginfo_conn_void,                      ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getOcspResponse,         arginfo_conn_void,                      ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getSignedCertTimestamps, arginfo_conn_void,                      ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getPeerCertificate,      arginfo_conn_void,                      ZEND_ACC_PUBLIC)
    PHP_ME(Connection, getPeerCertificateChain, arginfo_conn_void,                      ZEND_ACC_PUBLIC)
    PHP_ME(Connection, exportKeyingMaterial,    arginfo_conn_export_keying_material,     ZEND_ACC_PUBLIC)
    PHP_ME(Connection, setRenegotiateMode,      arginfo_conn_set_reneg_mode,             ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry bssl_session_methods[] = {
    PHP_ME(Session, fromBytes, arginfo_session_from_bytes, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Session, toBytes,   arginfo_session_void,       ZEND_ACC_PUBLIC)
    PHP_ME(Session, getId,     arginfo_session_void,       ZEND_ACC_PUBLIC)
    PHP_ME(Session, getTimeout, arginfo_session_void,      ZEND_ACC_PUBLIC)
    PHP_ME(Session, hasTicket, arginfo_session_void,       ZEND_ACC_PUBLIC)
    PHP_FE_END
};

/* --------------------------------------------------------------------------
 * Module lifecycle
 * ------------------------------------------------------------------------ */

PHP_MINIT_FUNCTION(boringssl) {
    zend_class_entry ce;

    /* Exception class */
    INIT_NS_CLASS_ENTRY(ce, "BoringSSL", "Exception", NULL);
    bssl_exception_ce = zend_register_internal_class_ex(&ce, spl_ce_RuntimeException);

    /* Context class */
    INIT_NS_CLASS_ENTRY(ce, "BoringSSL", "Context", bssl_ctx_methods);
    bssl_ctx_ce = zend_register_internal_class(&ce);
    bssl_ctx_ce->create_object = bssl_ctx_create;
    bssl_ctx_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NO_DYNAMIC_PROPERTIES;

    memcpy(&bssl_ctx_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    bssl_ctx_handlers.offset = XtOffsetOf(bssl_ctx_obj, std);
    bssl_ctx_handlers.free_obj = bssl_ctx_free;
    bssl_ctx_handlers.clone_obj = NULL;

    /* Connection class */
    INIT_NS_CLASS_ENTRY(ce, "BoringSSL", "Connection", bssl_conn_methods);
    bssl_conn_ce = zend_register_internal_class(&ce);
    bssl_conn_ce->create_object = bssl_conn_create;
    bssl_conn_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NO_DYNAMIC_PROPERTIES;

    memcpy(&bssl_conn_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    bssl_conn_handlers.offset = XtOffsetOf(bssl_conn_obj, std);
    bssl_conn_handlers.free_obj = bssl_conn_free;
    bssl_conn_handlers.clone_obj = NULL;

    /* Session class */
    INIT_NS_CLASS_ENTRY(ce, "BoringSSL", "Session", bssl_session_methods);
    bssl_session_ce = zend_register_internal_class(&ce);
    bssl_session_ce->create_object = bssl_session_create;
    bssl_session_ce->ce_flags |= ZEND_ACC_FINAL | ZEND_ACC_NO_DYNAMIC_PROPERTIES;

    memcpy(&bssl_session_handlers, &std_object_handlers, sizeof(zend_object_handlers));
    bssl_session_handlers.offset = XtOffsetOf(bssl_session_obj, std);
    bssl_session_handlers.free_obj = bssl_session_free;
    bssl_session_handlers.clone_obj = NULL;

    bssl_ctx_ex_data_idx = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    /* Protocol version constants */
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "TLS1_VERSION",   TLS1_VERSION,   CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "TLS1_1_VERSION", TLS1_1_VERSION, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "TLS1_2_VERSION", TLS1_2_VERSION, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "TLS1_3_VERSION", TLS1_3_VERSION, CONST_CS | CONST_PERSISTENT);

    /* Certificate compression algorithm IDs */
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "CERT_COMPRESS_ZLIB",   1, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "CERT_COMPRESS_BROTLI", 2, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "CERT_COMPRESS_ZSTD",   3, CONST_CS | CONST_PERSISTENT);

    /* Signature algorithm IDs (IANA TLS SignatureScheme values) */
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SIGALG_ECDSA_SECP256R1_SHA256", 0x0403, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SIGALG_RSA_PSS_RSAE_SHA256",    0x0804, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SIGALG_RSA_PKCS1_SHA256",       0x0401, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SIGALG_ECDSA_SECP384R1_SHA384", 0x0503, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SIGALG_RSA_PSS_RSAE_SHA384",    0x0805, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SIGALG_RSA_PKCS1_SHA384",       0x0501, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SIGALG_RSA_PSS_RSAE_SHA512",    0x0806, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SIGALG_RSA_PKCS1_SHA512",       0x0601, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SIGALG_RSA_PKCS1_SHA1",         0x0201, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SIGALG_ED25519",                0x0807, CONST_CS | CONST_PERSISTENT);

    /* Verify mode constants */
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "VERIFY_NONE",            SSL_VERIFY_NONE,                CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "VERIFY_PEER",            SSL_VERIFY_PEER,                CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "VERIFY_FAIL_IF_NO_CERT", SSL_VERIFY_FAIL_IF_NO_PEER_CERT, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "VERIFY_CLIENT_ONCE",     SSL_VERIFY_CLIENT_ONCE,         CONST_CS | CONST_PERSISTENT);

    /* ECH status constants */
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "ECH_STATUS_SUCCESS",        1, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "ECH_STATUS_REJECTED",       2, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "ECH_STATUS_NOT_NEGOTIATED", 3, CONST_CS | CONST_PERSISTENT);

    /* Early data status constants */
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "EARLY_DATA_NOT_SENT",  0, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "EARLY_DATA_REJECTED",  1, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "EARLY_DATA_ACCEPTED",  2, CONST_CS | CONST_PERSISTENT);

    /* X509 verification result constants */
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_OK", X509_V_OK, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT", X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_ERR_CERT_NOT_YET_VALID", X509_V_ERR_CERT_NOT_YET_VALID, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_ERR_CERT_HAS_EXPIRED", X509_V_ERR_CERT_HAS_EXPIRED, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT", X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN", X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY", X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE", X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_ERR_CERT_CHAIN_TOO_LONG", X509_V_ERR_CERT_CHAIN_TOO_LONG, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_ERR_CERT_REVOKED", X509_V_ERR_CERT_REVOKED, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_ERR_INVALID_CA", X509_V_ERR_INVALID_CA, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "X509_V_ERR_HOSTNAME_MISMATCH", X509_V_ERR_HOSTNAME_MISMATCH, CONST_CS | CONST_PERSISTENT);

    /* SSL option flags */
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SSL_OP_NO_TICKET", SSL_OP_NO_TICKET, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SSL_OP_CIPHER_SERVER_PREFERENCE", SSL_OP_CIPHER_SERVER_PREFERENCE, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SSL_OP_ALL", SSL_OP_ALL, CONST_CS | CONST_PERSISTENT);

    /* Renegotiation mode constants */
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "RENEGOTIATE_NEVER", ssl_renegotiate_never, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "RENEGOTIATE_ONCE", ssl_renegotiate_once, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "RENEGOTIATE_FREELY", ssl_renegotiate_freely, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "RENEGOTIATE_IGNORE", ssl_renegotiate_ignore, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "RENEGOTIATE_EXPLICIT", ssl_renegotiate_explicit, CONST_CS | CONST_PERSISTENT);

    /* Session cache mode constants */
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SESS_CACHE_OFF", SSL_SESS_CACHE_OFF, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SESS_CACHE_CLIENT", SSL_SESS_CACHE_CLIENT, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SESS_CACHE_SERVER", SSL_SESS_CACHE_SERVER, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("BoringSSL", "SESS_CACHE_BOTH", SSL_SESS_CACHE_BOTH, CONST_CS | CONST_PERSISTENT);

#ifdef HAVE_BORINGSSL_QUIC
    bssl_quic_minit(module_number);
#endif

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(boringssl) {
    return SUCCESS;
}

PHP_MINFO_FUNCTION(boringssl) {
    php_info_print_table_start();
    php_info_print_table_header(2, "BoringSSL support", "enabled");
    php_info_print_table_row(2, "Extension version", PHP_BORINGSSL_VERSION);
    php_info_print_table_row(2, "BoringSSL", "yes (Google BoringSSL)");
#ifdef HAVE_BROTLI
    php_info_print_table_row(2, "Cert compression: brotli", "yes");
#else
    php_info_print_table_row(2, "Cert compression: brotli", "no");
#endif
#ifdef HAVE_ZLIB
    php_info_print_table_row(2, "Cert compression: zlib", "yes");
#else
    php_info_print_table_row(2, "Cert compression: zlib", "no");
#endif
#ifdef HAVE_ZSTD
    php_info_print_table_row(2, "Cert compression: zstd", "yes");
#else
    php_info_print_table_row(2, "Cert compression: zstd", "no");
#endif
#ifdef HAVE_BORINGSSL_QUIC
    php_info_print_table_row(2, "QUIC transport (ngtcp2)", "yes");
#else
    php_info_print_table_row(2, "QUIC transport (ngtcp2)", "no");
#endif
    php_info_print_table_end();
}

static const zend_function_entry boringssl_functions[] = {
    /* Context */
    PHP_FE(boringssl_context_new,                       arginfo_fn_void)
    PHP_FE(boringssl_context_new_server,                arginfo_fn_void)
    PHP_FE(boringssl_context_set_cipher_list,            arginfo_fn_ctx_string)
    PHP_FE(boringssl_context_set_groups_list,             arginfo_fn_ctx_string)
    PHP_FE(boringssl_context_set_verify_algorithm_prefs, arginfo_fn_ctx_array)
    PHP_FE(boringssl_context_set_signing_algorithm_prefs, arginfo_fn_ctx_array)
    PHP_FE(boringssl_context_set_alpn_protos,             arginfo_fn_ctx_array)
    PHP_FE(boringssl_context_set_grease,                 arginfo_fn_ctx_bool)
    PHP_FE(boringssl_context_set_permute_extensions,     arginfo_fn_ctx_bool)
    PHP_FE(boringssl_context_add_application_settings,   arginfo_fn_ctx_app_settings)
    PHP_FE(boringssl_context_set_alps_use_new_codepoint, arginfo_fn_ctx_bool)
    PHP_FE(boringssl_context_add_cert_compression_alg,   arginfo_fn_ctx_long)
    PHP_FE(boringssl_context_set_ech_config_list,        arginfo_fn_ctx_string)
    PHP_FE(boringssl_context_set_min_proto_version,      arginfo_fn_ctx_long)
    PHP_FE(boringssl_context_set_max_proto_version,      arginfo_fn_ctx_long)
    PHP_FE(boringssl_context_set_early_data,             arginfo_fn_ctx_bool)
    PHP_FE(boringssl_context_use_certificate_file,       arginfo_fn_ctx_string)
    PHP_FE(boringssl_context_use_private_key_file,       arginfo_fn_ctx_string)
    PHP_FE(boringssl_context_load_verify_locations,      arginfo_fn_ctx_load_verify)
    PHP_FE(boringssl_context_set_verify,                 arginfo_fn_ctx_set_verify)
    PHP_FE(boringssl_context_set_default_verify_paths,     arginfo_fn_ctx)
    PHP_FE(boringssl_context_set_verify_depth,             arginfo_fn_ctx_long)
    PHP_FE(boringssl_context_set_options,                   arginfo_fn_ctx_long)
    PHP_FE(boringssl_context_clear_options,                 arginfo_fn_ctx_long)
    PHP_FE(boringssl_context_get_options,                   arginfo_fn_ctx)
    PHP_FE(boringssl_context_enable_ocsp_stapling,          arginfo_fn_ctx_bool)
    PHP_FE(boringssl_context_enable_signed_cert_timestamps, arginfo_fn_ctx_bool)
    PHP_FE(boringssl_context_set_keylog_file,               arginfo_fn_ctx_string)
    PHP_FE(boringssl_context_load_client_ca_file,           arginfo_fn_ctx_string)
    PHP_FE(boringssl_context_set_session_ticket_keys,       arginfo_fn_ctx_string)
    PHP_FE(boringssl_context_use_certificate_chain_pem,     arginfo_fn_ctx_string)
    PHP_FE(boringssl_context_use_private_key_pem,           arginfo_fn_ctx_string)
    /* Connection */
    PHP_FE(boringssl_new_connection,                     arginfo_fn_ctx)
    PHP_FE(boringssl_set_fd,                             arginfo_fn_conn_fd)
    PHP_FE(boringssl_set_stream,                         arginfo_fn_conn_stream)
    PHP_FE(boringssl_connect,                            arginfo_fn_conn)
    PHP_FE(boringssl_accept,                             arginfo_fn_conn)
    PHP_FE(boringssl_read,                               arginfo_fn_conn_read)
    PHP_FE(boringssl_write,                              arginfo_fn_conn_write)
    PHP_FE(boringssl_pending,                            arginfo_fn_conn)
    PHP_FE(boringssl_shutdown,                           arginfo_fn_conn)
    PHP_FE(boringssl_get_alpn_proto,                     arginfo_fn_conn)
    PHP_FE(boringssl_get_cipher,                         arginfo_fn_conn)
    PHP_FE(boringssl_get_group,                          arginfo_fn_conn)
    PHP_FE(boringssl_get_version,                        arginfo_fn_conn)
    PHP_FE(boringssl_get_session,                        arginfo_fn_conn)
    PHP_FE(boringssl_set_session,                        arginfo_fn_conn_session)
    PHP_FE(boringssl_set_hostname,                          arginfo_fn_conn_hostname)
    PHP_FE(boringssl_get_verify_result,                     arginfo_fn_conn)
    PHP_FE(boringssl_session_reused,                        arginfo_fn_conn)
    PHP_FE(boringssl_peek,                                  arginfo_fn_conn_read)
    PHP_FE(boringssl_key_update,                            arginfo_fn_conn)
    PHP_FE(boringssl_get_ocsp_response,                     arginfo_fn_conn)
    PHP_FE(boringssl_get_signed_cert_timestamps,            arginfo_fn_conn)
    PHP_FE(boringssl_get_peer_certificate,                  arginfo_fn_conn)
    PHP_FE(boringssl_get_peer_certificate_chain,            arginfo_fn_conn)
    PHP_FE(boringssl_export_keying_material,                arginfo_fn_conn_export_km)
    PHP_FE(boringssl_set_renegotiate_mode,                  arginfo_fn_conn_long)
    /* Session */
    PHP_FE(boringssl_session_from_bytes,                 arginfo_fn_session_from_bytes)
    PHP_FE(boringssl_session_to_bytes,                   arginfo_fn_session)
    PHP_FE(boringssl_session_get_id,                     arginfo_fn_session)
    PHP_FE(boringssl_session_get_timeout,                arginfo_fn_session)
    PHP_FE(boringssl_session_has_ticket,                 arginfo_fn_session)
    PHP_FE_END
};

zend_module_entry boringssl_module_entry = {
    STANDARD_MODULE_HEADER,
    "boringssl",
    boringssl_functions,
    PHP_MINIT(boringssl),
    PHP_MSHUTDOWN(boringssl),
    NULL, /* RINIT */
    NULL, /* RSHUTDOWN */
    PHP_MINFO(boringssl),
    PHP_BORINGSSL_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_BORINGSSL
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(boringssl)
#endif
