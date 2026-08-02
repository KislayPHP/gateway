PHP_ARG_ENABLE(kislayphp_gateway, whether to enable kislayphp_gateway,
[  --enable-kislayphp_gateway   Enable kislayphp_gateway support])

if test "$PHP_KISLAYPHP_GATEWAY" != "no"; then
  PHP_REQUIRE_CXX()

  CIVETWEB_INCLUDE_DIR=`pwd`/third_party/civetweb/include
  PHP_ADD_INCLUDE($CIVETWEB_INCLUDE_DIR)

  PKG_CHECK_MODULES([OPENSSL], [openssl])
  PHP_EVAL_INCLINE($OPENSSL_CFLAGS)
  PHP_EVAL_LIBLINE($OPENSSL_LIBS, KISLAYPHP_GATEWAY_SHARED_LIBADD)
  PHP_ADD_LIBRARY(stdc++,, KISLAYPHP_GATEWAY_SHARED_LIBADD)
  PHP_SUBST(KISLAYPHP_GATEWAY_SHARED_LIBADD)

  dnl -fvisibility=hidden + -DCIVETWEB_API=: civetweb.c exports ~200
  dnl non-static C functions (mg_start, mg_read, ...) with default (public)
  dnl visibility, explicitly re-asserted by civetweb.h's own
  dnl CIVETWEB_API macro regardless of -fvisibility. PHP extension bundles
  dnl link with -flat_namespace on this platform (confirmed in the actual
  dnl link command), so when 2+ extensions that each vendor their own copy
  dnl of civetweb.c are loaded into the same process (e.g. this extension
  dnl alongside core or socket, which also embed civetweb), the dynamic
  dnl linker can resolve a call in ONE extension's object code to the
  dnl OTHER extension's same-named symbol - silently running the wrong
  dnl compiled civetweb (confirmed empirically this session while
  dnl debugging kislayphp/socket). Pre-defining CIVETWEB_API as empty
  dnl defers to -fvisibility=hidden instead, without touching the vendored
  dnl header/source; get_module() (PHP's own dlopen()-based loader only
  dnl needs that one symbol) stays exported via ZEND_GET_MODULE's own
  dnl ZEND_DLEXPORT, independent of this flag.
  CFLAGS="$CFLAGS -DOPENSSL_API_3_0 -fvisibility=hidden -DCIVETWEB_API="
  CXXFLAGS="$CXXFLAGS -DOPENSSL_API_3_0 -std=c++17 -fvisibility=hidden -DCIVETWEB_API="
  if test -f ../rpc/gen/discovery.pb.cc; then
    RPC_GEN_DIR=`pwd`/../rpc/gen
    PHP_ADD_INCLUDE($RPC_GEN_DIR)
    PHP_ADD_INCLUDE(`pwd`/../rpc)
    PKG_CHECK_MODULES([GRPC], [grpc++])
    PHP_EVAL_INCLINE($GRPC_CFLAGS)
    PHP_EVAL_LIBLINE($GRPC_LIBS, KISLAYPHP_GATEWAY_SHARED_LIBADD)
    CXXFLAGS="$CXXFLAGS -DKISLAYPHP_RPC"
    RPC_SRCS="../rpc/gen/discovery.pb.cc ../rpc/gen/discovery.grpc.pb.cc"
  else
    AC_MSG_WARN([RPC stubs not found. Building without RPC service resolution support.])
    RPC_SRCS=""
  fi

  PHP_NEW_EXTENSION(kislayphp_gateway, kislayphp_gateway.cpp third_party/civetweb/src/civetweb.c $RPC_SRCS, $ext_shared)
fi
