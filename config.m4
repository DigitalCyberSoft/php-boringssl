PHP_ARG_WITH([boringssl],
  [for BoringSSL support],
  [AS_HELP_STRING([--with-boringssl@<:@=DIR@:>@],
    [Include BoringSSL support. DIR is the path to the BoringSSL build directory])])

if test "$PHP_BORINGSSL" != "no"; then

  if test "$PHP_BORINGSSL" = "yes"; then
    BORINGSSL_DIR="/usr/local"
  else
    BORINGSSL_DIR="$PHP_BORINGSSL"
  fi

  dnl Check for BoringSSL headers
  AC_MSG_CHECKING([for BoringSSL headers])
  if test -f "$BORINGSSL_DIR/include/openssl/ssl.h"; then
    BORINGSSL_INCDIR="$BORINGSSL_DIR/include"
    AC_MSG_RESULT([found in $BORINGSSL_INCDIR])
  else
    AC_MSG_ERROR([BoringSSL headers not found. Specify the path to BoringSSL with --with-boringssl=DIR])
  fi

  dnl Verify this is actually BoringSSL, not OpenSSL
  AC_MSG_CHECKING([whether this is BoringSSL])
  old_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS -I$BORINGSSL_INCDIR"
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <openssl/base.h>]],
      [[
        #ifndef OPENSSL_IS_BORINGSSL
        #error Not BoringSSL
        #endif
      ]])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_ERROR([The specified library is not BoringSSL. This extension requires BoringSSL, not OpenSSL or LibreSSL.])])
  CPPFLAGS="$old_CPPFLAGS"

  dnl Look for static libraries (preferred) or shared
  AC_MSG_CHECKING([for BoringSSL libraries])
  BORINGSSL_SSL_LIB=""
  BORINGSSL_CRYPTO_LIB=""

  dnl Check build/ subdirectory first (cmake build layout)
  for libdir in "$BORINGSSL_DIR/build" "$BORINGSSL_DIR/build/ssl" "$BORINGSSL_DIR/lib" "$BORINGSSL_DIR/build/lib" "$BORINGSSL_DIR"; do
    if test -f "$libdir/libssl.a"; then
      BORINGSSL_SSL_LIB="$libdir/libssl.a"
      break
    fi
  done

  for libdir in "$BORINGSSL_DIR/build" "$BORINGSSL_DIR/build/crypto" "$BORINGSSL_DIR/lib" "$BORINGSSL_DIR/build/lib" "$BORINGSSL_DIR"; do
    if test -f "$libdir/libcrypto.a"; then
      BORINGSSL_CRYPTO_LIB="$libdir/libcrypto.a"
      break
    fi
  done

  if test -z "$BORINGSSL_SSL_LIB" || test -z "$BORINGSSL_CRYPTO_LIB"; then
    AC_MSG_ERROR([BoringSSL static libraries (libssl.a, libcrypto.a) not found under $BORINGSSL_DIR])
  fi
  AC_MSG_RESULT([ssl: $BORINGSSL_SSL_LIB, crypto: $BORINGSSL_CRYPTO_LIB])

  PHP_ADD_INCLUDE($BORINGSSL_INCDIR)

  dnl Required system libraries
  PHP_ADD_LIBRARY(pthread, 1, BORINGSSL_SHARED_LIBADD)
  PHP_ADD_LIBRARY(dl, 1, BORINGSSL_SHARED_LIBADD)
  PHP_ADD_LIBRARY(stdc++, 1, BORINGSSL_SHARED_LIBADD)

  dnl Optional compression libraries for cert compression
  AC_CHECK_LIB(brotlienc, BrotliEncoderCompress, [
    AC_CHECK_LIB(brotlidec, BrotliDecoderDecompress, [
      PHP_ADD_LIBRARY(brotlienc, 1, BORINGSSL_SHARED_LIBADD)
      PHP_ADD_LIBRARY(brotlidec, 1, BORINGSSL_SHARED_LIBADD)
      AC_DEFINE([HAVE_BROTLI], [1], [Whether brotli is available for cert compression])
    ])
  ])

  AC_CHECK_LIB(z, compress, [
    PHP_ADD_LIBRARY(z, 1, BORINGSSL_SHARED_LIBADD)
    AC_DEFINE([HAVE_ZLIB], [1], [Whether zlib is available for cert compression])
  ])

  AC_CHECK_LIB(zstd, ZSTD_compress, [
    PHP_ADD_LIBRARY(zstd, 1, BORINGSSL_SHARED_LIBADD)
    AC_DEFINE([HAVE_ZSTD], [1], [Whether zstd is available for cert compression])
  ])

  dnl QUIC transport via ngtcp2 (auto-detect)
  BORINGSSL_QUIC_SOURCES=""
  dnl Look for ngtcp2 alongside BoringSSL
  NGTCP2_DIR=""
  for ngtcp2_try in "$BORINGSSL_DIR/../ngtcp2" "$abs_srcdir/deps/ngtcp2" "deps/ngtcp2"; do
    if test -d "$ngtcp2_try/build"; then
      NGTCP2_DIR="$ngtcp2_try"
      break
    fi
  done
  NGTCP2_LIB=""
  NGTCP2_CRYPTO_LIB=""

  AC_MSG_CHECKING([for ngtcp2 with BoringSSL crypto backend])
  if test -f "$NGTCP2_DIR/build/lib/libngtcp2.a" && \
     test -f "$NGTCP2_DIR/build/crypto/boringssl/libngtcp2_crypto_boringssl.a"; then
    NGTCP2_LIB="$NGTCP2_DIR/build/lib/libngtcp2.a"
    NGTCP2_CRYPTO_LIB="$NGTCP2_DIR/build/crypto/boringssl/libngtcp2_crypto_boringssl.a"
    AC_MSG_RESULT([yes])

    dnl ngtcp2 include paths
    PHP_ADD_INCLUDE($NGTCP2_DIR/lib/includes)
    PHP_ADD_INCLUDE($NGTCP2_DIR/build/lib/includes)
    PHP_ADD_INCLUDE($NGTCP2_DIR/crypto/includes)

    AC_DEFINE([HAVE_BORINGSSL_QUIC], [1], [Whether QUIC transport support is enabled via ngtcp2])
    BORINGSSL_QUIC_SOURCES=" quic.c"
  else
    AC_MSG_RESULT([no (ngtcp2 not built, QUIC support disabled)])
  fi

  dnl Prepend static libs: ngtcp2_crypto_boringssl -> ngtcp2 -> boringssl (link order matters)
  BORINGSSL_SHARED_LIBADD="$NGTCP2_CRYPTO_LIB $NGTCP2_LIB $BORINGSSL_SSL_LIB $BORINGSSL_CRYPTO_LIB $BORINGSSL_SHARED_LIBADD"

  dnl BoringSSL is C++ internally, may need text relocations
  LDFLAGS="$LDFLAGS -Wl,-z,notext"

  PHP_SUBST([BORINGSSL_SHARED_LIBADD])
  PHP_NEW_EXTENSION(boringssl, boringssl.c$BORINGSSL_QUIC_SOURCES, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi
