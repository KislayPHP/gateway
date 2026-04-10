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
  PHP_ADD_INCLUDE(`pwd`/engine/epoll)
  PHP_ADD_INCLUDE(`pwd`/engine/core)
  PHP_ADD_INCLUDE(`pwd`/engine/interface)
  PHP_ADD_INCLUDE(`pwd`/engine/kqueue)

  CFLAGS="$CFLAGS -DOPENSSL_API_3_0"
  CXXFLAGS="$CXXFLAGS -DOPENSSL_API_3_0"
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

  EPOLL_SRCS="engine/core/connection.cpp engine/core/http_parser.cpp engine/core/timer_wheel.cpp engine/core/discovery_manager.cpp engine/core/proxy_engine.cpp engine/epoll/epoll_loop.cpp engine/kqueue/kqueue_loop.cpp engine/epoll/epoll_server.cpp"

  PHP_NEW_EXTENSION(kislayphp_gateway, kislayphp_gateway.cpp third_party/civetweb/src/civetweb.c $EPOLL_SRCS $RPC_SRCS, $ext_shared)
fi
