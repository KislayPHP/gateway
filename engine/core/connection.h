#pragma once

#include "buffer.h"
#include "http_parser.h"
#include "router_adapter.h"

#include <cstdint>
#include <cstring>

typedef struct ssl_st SSL;

namespace kislay {
namespace gateway {
namespace core {

static constexpr std::size_t kHeaderBufferBytes = 8192;
static constexpr std::size_t kMaxHeaderRefs = 64;

enum class ConnState {
    HandshakeClientTls = 0,
    ReadClientHeaders,
    ReadClientBody,
    ResolveRoute,
    ConnectUpstream,
    WriteUpstream,
    ReadUpstream,
    SpliceResponseBody,
    WriteClient,
    Done,
    Error
};

struct Connection;

struct CoreTag {
    enum Kind {
        Listener = 0,
        Client,
        Upstream,
    } kind;
    Connection *conn;
};

struct ConnectionBuffers {
    FixedBuffer<kHeaderBufferBytes> client_buffer;
    FixedBuffer<kHeaderBufferBytes> upstream_buffer;
    RequestHead request;
    ResponseHead response;
    HeaderRef request_headers[kMaxHeaderRefs];
    HeaderRef response_headers[kMaxHeaderRefs];

    ConnectionBuffers();
    void Reset();
};

struct Connection {
    static constexpr uint32_t kNoChunk = UINT32_MAX;

    uint32_t generation;
    int client_fd;
    int upstream_fd;
    ConnState state;
    uint32_t client_events;
    uint32_t upstream_events;
    uint32_t client_token_generation;
    uint32_t upstream_token_generation;
    ConnectionBuffers *buffers;
    const RouteSnapshotEntry *route;
    const UpstreamTarget *upstream_target;
    CoreTag client_tag;
    CoreTag upstream_tag;
    int pipefd[2];
    uint32_t pipe_buffered_bytes;
    uint32_t pipe_capacity_bytes;
    uint32_t response_header_bytes;
    uint32_t response_header_forwarded;
    bool request_parsed;
    bool response_parsed;
    bool in_use;
    bool client_registered;
    bool upstream_registered;
    bool client_keep_alive;
    bool keep_alive_idle;
    bool safe_client_keep_alive;
    bool safe_upstream_keep_alive;
    bool close_after_response;
    bool pipelined_bytes;
    bool upstream_connected;
    bool saw_client_eof;
    bool saw_upstream_eof;
    bool splice_enabled;
    bool pipe_initialized;
    bool splice_eof;
    bool passthrough_response_headers;
    bool response_started;
    bool client_tls_enabled;
    bool client_tls_ready;
    bool client_tls_want_read;
    bool client_tls_want_write;
    SSL *client_ssl;
    uint32_t request_chunk_head;
    uint32_t request_chunk_tail;
    uint32_t request_chunk_count;
    uint32_t response_chunk_head;
    uint32_t response_chunk_tail;
    uint32_t response_chunk_count;
    uint64_t request_body_expected;
    uint64_t request_body_forwarded;
    uint64_t response_body_expected;
    uint64_t response_body_forwarded;
    uint64_t remaining_bytes;
    uint64_t last_progress_ms;
    uint64_t deadline_ms;
    uint32_t timer_prev;
    uint32_t timer_next;
    uint32_t timer_slot;
    bool timer_armed;

    Connection();
    void Reset(int fd);
    void ResetForNextRequest();
};

} // namespace core
} // namespace gateway
} // namespace kislay
