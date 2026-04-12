#include "connection.h"

namespace kislay {
namespace gateway {
namespace core {

ConnectionBuffers::ConnectionBuffers() {
    Reset();
}

void ConnectionBuffers::Reset() {
    client_buffer.clear();
    upstream_buffer.clear();
    request = RequestHead();
    response = ResponseHead();
}

Connection::Connection()
    : generation(0),
      client_fd(-1),
      upstream_fd(-1),
      state(ConnState::ReadClientHeaders),
      client_events(0),
      upstream_events(0),
      client_token_generation(0),
      upstream_token_generation(0),
      buffers(nullptr),
      route(nullptr),
      upstream_target(nullptr),
      pipefd{-1, -1},
      pipe_buffered_bytes(0),
      pipe_capacity_bytes(65536),
      response_header_bytes(0),
      response_header_forwarded(0),
      request_parsed(false),
      response_parsed(false),
      in_use(false),
      client_registered(false),
      upstream_registered(false),
      client_keep_alive(false),
      keep_alive_idle(false),
      safe_client_keep_alive(false),
      safe_upstream_keep_alive(false),
      close_after_response(true),
      pipelined_bytes(false),
      upstream_connected(false),
      saw_client_eof(false),
      saw_upstream_eof(false),
      splice_enabled(false),
      pipe_initialized(false),
      splice_eof(false),
      passthrough_response_headers(false),
      response_started(false),
      request_chunk_head(Connection::kNoChunk),
      request_chunk_tail(Connection::kNoChunk),
      request_chunk_count(0),
      response_chunk_head(Connection::kNoChunk),
      response_chunk_tail(Connection::kNoChunk),
      response_chunk_count(0),
      request_body_expected(0),
      request_body_forwarded(0),
      response_body_expected(0),
      response_body_forwarded(0),
      remaining_bytes(0),
      last_progress_ms(0),
      deadline_ms(0),
      timer_prev(UINT32_MAX),
      timer_next(UINT32_MAX),
      timer_slot(UINT32_MAX),
      timer_armed(false) {
    client_tag.kind = CoreTag::Client;
    client_tag.conn = this;
    upstream_tag.kind = CoreTag::Upstream;
    upstream_tag.conn = this;
}

void Connection::Reset(int fd) {
    if (fd >= 0) {
        ++generation;
    }
    client_fd = fd;
    upstream_fd = -1;
    state = ConnState::ReadClientHeaders;
    if (buffers != nullptr) {
        buffers->Reset();
    }
    route = nullptr;
    upstream_target = nullptr;
    client_events = 0;
    upstream_events = 0;
    client_token_generation = 0;
    upstream_token_generation = 0;
    pipe_buffered_bytes = 0;
    pipe_capacity_bytes = pipe_initialized ? pipe_capacity_bytes : 65536;
    response_header_bytes = 0;
    response_header_forwarded = 0;
    request_parsed = false;
    response_parsed = false;
    in_use = fd >= 0;
    client_registered = false;
    upstream_registered = false;
    client_keep_alive = false;
    keep_alive_idle = false;
    safe_client_keep_alive = false;
    safe_upstream_keep_alive = false;
    close_after_response = true;
    pipelined_bytes = false;
    upstream_connected = false;
    saw_client_eof = false;
    saw_upstream_eof = false;
    splice_enabled = false;
    pipe_initialized = pipefd[0] >= 0 && pipefd[1] >= 0;
    splice_eof = false;
    passthrough_response_headers = false;
    response_started = false;
    request_chunk_head = kNoChunk;
    request_chunk_tail = kNoChunk;
    request_chunk_count = 0;
    response_chunk_head = kNoChunk;
    response_chunk_tail = kNoChunk;
    response_chunk_count = 0;
    request_body_expected = 0;
    request_body_forwarded = 0;
    response_body_expected = 0;
    response_body_forwarded = 0;
    remaining_bytes = 0;
    last_progress_ms = 0;
    deadline_ms = 0;
    timer_prev = UINT32_MAX;
    timer_next = UINT32_MAX;
    timer_slot = UINT32_MAX;
    timer_armed = false;
}

void Connection::ResetForNextRequest() {
    const int fd = client_fd;
    const uint32_t events = client_events;
    const bool registered = client_registered;
    const uint32_t token_generation = client_token_generation;
    const uint64_t last_progress = last_progress_ms;
    Reset(fd);
    client_events = events;
    client_registered = registered;
    client_token_generation = token_generation;
    in_use = fd >= 0;
    keep_alive_idle = true;
    last_progress_ms = last_progress;
}

} // namespace core
} // namespace gateway
} // namespace kislay
