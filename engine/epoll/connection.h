#pragma once

#include "buffer.h"
#include "http_parser.h"
#include "router_adapter.h"

#include <cstdint>
#include <cstring>

namespace kislay {
namespace gateway {
namespace epoll {

enum class ConnState {
    ReadClientHeaders = 0,
    ReadClientBody,
    ResolveRoute,
    ConnectUpstream,
    WriteUpstream,
    ReadUpstream,
    WriteClient,
    Done,
    Error
};

struct Connection;

struct EpollTag {
    enum Kind {
        Listener = 0,
        Client,
        Upstream,
    } kind;
    Connection *conn;
};

struct Connection {
    uint32_t generation;
    int client_fd;
    int upstream_fd;
    ConnState state;
    FixedBuffer<32768> client_buffer;
    FixedBuffer<32768> upstream_buffer;
    RequestHead request;
    ResponseHead response;
    HeaderRef request_headers[64];
    HeaderRef response_headers[64];
    const RouteSnapshotEntry *route;
    const UpstreamTarget *upstream_target;
    EpollTag client_tag;
    EpollTag upstream_tag;
    uint32_t client_events;
    uint32_t upstream_events;
    bool request_parsed;
    bool response_parsed;
    bool client_keep_alive;
    bool safe_client_keep_alive;
    bool safe_upstream_keep_alive;
    bool close_after_response;
    bool pipelined_bytes;
    bool upstream_connected;
    bool saw_client_eof;
    bool saw_upstream_eof;
    bool passthrough_response_headers;
    uint64_t request_body_expected;
    uint64_t request_body_forwarded;
    uint64_t response_body_expected;
    uint64_t response_body_forwarded;
    uint32_t response_header_bytes;
    uint32_t response_header_forwarded;
    uint64_t last_activity_ms;

    Connection();
    void Reset(int fd);
    void ResetForNextRequest();
};

} // namespace epoll
} // namespace gateway
} // namespace kislay
