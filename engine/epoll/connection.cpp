#include "connection.h"

namespace kislay {
namespace gateway {
namespace epoll {

Connection::Connection()
    : generation(0),
      client_fd(-1),
      upstream_fd(-1),
      state(ConnState::ReadClientHeaders),
      route(nullptr),
      upstream_target(nullptr),
      client_events(0),
      upstream_events(0),
      request_parsed(false),
      response_parsed(false),
      client_keep_alive(false),
      safe_client_keep_alive(false),
      safe_upstream_keep_alive(false),
      close_after_response(true),
      pipelined_bytes(false),
      upstream_connected(false),
      saw_client_eof(false),
      saw_upstream_eof(false),
      passthrough_response_headers(false),
      request_body_expected(0),
      request_body_forwarded(0),
      response_body_expected(0),
      response_body_forwarded(0),
      response_header_bytes(0),
      response_header_forwarded(0),
      last_activity_ms(0) {
    request = RequestHead();
    response = ResponseHead();
    client_tag.kind = EpollTag::Client;
    client_tag.conn = this;
    upstream_tag.kind = EpollTag::Upstream;
    upstream_tag.conn = this;
}

void Connection::Reset(int fd) {
    if (fd >= 0) {
        ++generation;
    }
    client_fd = fd;
    upstream_fd = -1;
    state = ConnState::ReadClientHeaders;
    client_buffer.clear();
    upstream_buffer.clear();
    route = nullptr;
    upstream_target = nullptr;
    client_events = 0;
    upstream_events = 0;
    request_parsed = false;
    response_parsed = false;
    client_keep_alive = false;
    safe_client_keep_alive = false;
    safe_upstream_keep_alive = false;
    close_after_response = true;
    pipelined_bytes = false;
    upstream_connected = false;
    saw_client_eof = false;
    saw_upstream_eof = false;
    passthrough_response_headers = false;
    request_body_expected = 0;
    request_body_forwarded = 0;
    response_body_expected = 0;
    response_body_forwarded = 0;
    response_header_bytes = 0;
    response_header_forwarded = 0;
    request = RequestHead();
    response = ResponseHead();
}

void Connection::ResetForNextRequest() {
    Reset(client_fd);
}

} // namespace epoll
} // namespace gateway
} // namespace kislay
