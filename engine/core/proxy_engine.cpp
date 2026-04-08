#include "proxy_engine.h"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#if defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#ifdef __linux__
#include <sched.h>
#endif

namespace kislay {
namespace gateway {
namespace core {

namespace {

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static uint64_t now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000ull + static_cast<uint64_t>(ts.tv_nsec / 1000000ull);
}

static uint32_t fnv1a32(const char *data, std::size_t len) {
    uint32_t hash = 2166136261u;
    for (std::size_t i = 0; i < len; ++i) {
        hash ^= static_cast<unsigned char>(data[i]);
        hash *= 16777619u;
    }
    return hash;
}

static int online_cpu_count() {
    const long count = sysconf(_SC_NPROCESSORS_ONLN);
    return count > 0 ? static_cast<int>(count) : 1;
}

static bool emit_worker_stats() {
    static int cached = -1;
    if (cached == -1) {
        const char *value = std::getenv("KISLAY_GATEWAY_EPOLL_STATS");
        cached = (value != nullptr && *value != '\0' && *value != '0') ? 1 : 0;
    }
    return cached == 1;
}

static const uint64_t kClientHeaderTimeoutMs = 5000ull;
static const uint64_t kClientBodyTimeoutMs = 15000ull;
static const uint64_t kUpstreamConnectTimeoutMs = 5000ull;
static const uint64_t kUpstreamResponseTimeoutMs = 30000ull;
static const uint64_t kClientWriteTimeoutMs = 30000ull;
static const uint64_t kIdleKeepAliveTimeoutMs = 15000ull;
static const uint64_t kUpstreamPoolIdleTimeoutMs = 15000ull;
static const std::size_t kMaxIdleUpstreamsPerKey = 8u;

enum class TimeoutKind {
    None = 0,
    IdleKeepAlive,
    ClientHeaders,
    ClientBody,
    UpstreamConnect,
    UpstreamResponse,
    ClientWrite,
};

static void close_fd(int &fd) {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

static bool set_nonblocking(int fd, std::string *error_out) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        if (error_out != nullptr) {
            *error_out = std::strerror(errno);
        }
        return false;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        if (error_out != nullptr) {
            *error_out = std::strerror(errno);
        }
        return false;
    }
    return true;
}

static bool suppress_sigpipe(int fd, std::string *error_out) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) != 0) {
        if (error_out != nullptr) {
            *error_out = std::strerror(errno);
        }
        return false;
    }
#else
    (void) fd;
    (void) error_out;
#endif
    return true;
}

static bool set_tcp_nodelay(int fd) {
    int one = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0;
}

static bool build_sockaddr(const char *host,
                           uint16_t port,
                           sockaddr_storage *storage,
                           socklen_t *storage_len,
                           std::string *error_out) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *result = nullptr;
    char port_buf[16];
    std::snprintf(port_buf, sizeof(port_buf), "%u", static_cast<unsigned>(port));
    const int rc = getaddrinfo(host, port_buf, &hints, &result);
    if (rc != 0 || result == nullptr) {
        if (error_out != nullptr) {
            *error_out = gai_strerror(rc);
        }
        if (result != nullptr) {
            freeaddrinfo(result);
        }
        return false;
    }
    std::memcpy(storage, result->ai_addr, result->ai_addrlen);
    *storage_len = static_cast<socklen_t>(result->ai_addrlen);
    freeaddrinfo(result);
    return true;
}

static void append_literal(FixedBuffer<32768> &buffer, const char *text) {
    const std::size_t len = std::strlen(text);
    if (buffer.writable() < len) {
        return;
    }
    std::memcpy(buffer.write_ptr(), text, len);
    buffer.produced(len);
}

static void append_bytes(FixedBuffer<32768> &buffer, const char *data, std::size_t len) {
    if (buffer.writable() < len) {
        return;
    }
    std::memcpy(buffer.write_ptr(), data, len);
    buffer.produced(len);
}

static void append_uint(FixedBuffer<32768> &buffer, uint64_t value) {
    char tmp[32];
    std::snprintf(tmp, sizeof(tmp), "%llu", static_cast<unsigned long long>(value));
    append_literal(buffer, tmp);
}

static bool is_hop_header(const char *buffer, const HeaderRef &header) {
    return HeaderEquals(buffer, header, "Connection") ||
           HeaderEquals(buffer, header, "Keep-Alive") ||
           HeaderEquals(buffer, header, "Proxy-Connection") ||
           HeaderEquals(buffer, header, "Transfer-Encoding") ||
           HeaderEquals(buffer, header, "Upgrade") ||
           HeaderEquals(buffer, header, "TE") ||
           HeaderEquals(buffer, header, "Trailer");
}

static bool request_error_is_too_large(const char *error) {
    return error != nullptr &&
           (std::strcmp(error, "headers too large") == 0 || std::strcmp(error, "too many headers") == 0);
}

static bool timeout_trace_enabled() {
    static int cached = -1;
    if (cached == -1) {
        cached = std::getenv("KISLAY_GATEWAY_EPOLL_TRACE_TIMEOUTS") != nullptr ? 1 : 0;
    }
    return cached == 1;
}

static bool response_started_to_client(const Connection *conn) {
    return conn->response_started;
}

static void mark_progress(Connection *conn, uint64_t now) {
    conn->last_progress_ms = now;
    conn->keep_alive_idle = false;
}

} // namespace

struct WorkerRuntime {
    struct PoolKey {
        uint32_t host_hash;
        uint16_t port;
        uint8_t tls;

        bool operator==(const PoolKey &other) const {
            return host_hash == other.host_hash && port == other.port && tls == other.tls;
        }
    };

    struct PoolKeyHash {
        std::size_t operator()(const PoolKey &key) const {
            return static_cast<std::size_t>(key.host_hash) ^
                   (static_cast<std::size_t>(key.port) << 1) ^
                   (static_cast<std::size_t>(key.tls) << 17);
        }
    };

    struct PooledUpstream {
        int fd;
        uint64_t last_used_ms;

        PooledUpstream() : fd(-1), last_used_ms(0) {}
        PooledUpstream(int socket_fd, uint64_t used_ms) : fd(socket_fd), last_used_ms(used_ms) {}
    };

    std::unique_ptr<platform::EventLoop> loop;
    int listener_fd;
    int worker_index;
    std::vector<Connection> connections;
    std::vector<uint32_t> free_list;
    RouteSnapshot snapshot;
    std::size_t max_body_bytes;
    std::unordered_map<PoolKey, std::deque<PooledUpstream>, PoolKeyHash> upstream_pool;
    uint64_t total_requests;
    uint64_t active_connections;
    uint64_t peak_active_connections;
    uint64_t splice_hits;
    uint64_t splice_fallbacks;
    uint64_t header_passthrough_hits;
    uint64_t total_errors;
    uint64_t total_timeouts;
    uint64_t rejected_connections;
    uint64_t fallback_hits;

    WorkerRuntime()
        : listener_fd(-1),
          worker_index(0),
          max_body_bytes(0),
          total_requests(0),
          active_connections(0),
          peak_active_connections(0),
          splice_hits(0),
          splice_fallbacks(0),
          header_passthrough_hits(0),
          total_errors(0),
          total_timeouts(0),
          rejected_connections(0),
          fallback_hits(0) {}
};

namespace {

static uint64_t timeout_for_connection(const Connection *conn, TimeoutKind *kind_out) {
    TimeoutKind kind = TimeoutKind::None;
    uint64_t timeout_ms = 0;

    switch (conn->state) {
        case ConnState::ReadClientHeaders:
            if (conn->client_buffer.empty() && conn->keep_alive_idle) {
                kind = TimeoutKind::IdleKeepAlive;
                timeout_ms = kIdleKeepAliveTimeoutMs;
            } else {
                kind = TimeoutKind::ClientHeaders;
                timeout_ms = kClientHeaderTimeoutMs;
            }
            break;
        case ConnState::ConnectUpstream:
            kind = TimeoutKind::UpstreamConnect;
            timeout_ms = kUpstreamConnectTimeoutMs;
            break;
        case ConnState::WriteUpstream:
            if (conn->request_body_forwarded < conn->request_body_expected) {
                kind = TimeoutKind::ClientBody;
                timeout_ms = kClientBodyTimeoutMs;
            } else {
                kind = TimeoutKind::UpstreamResponse;
                timeout_ms = kUpstreamResponseTimeoutMs;
            }
            break;
        case ConnState::ReadUpstream:
        case ConnState::SpliceResponseBody:
            kind = TimeoutKind::UpstreamResponse;
            timeout_ms = kUpstreamResponseTimeoutMs;
            break;
        case ConnState::WriteClient:
            kind = TimeoutKind::ClientWrite;
            timeout_ms = kClientWriteTimeoutMs;
            break;
        default:
            break;
    }

    if (kind_out != nullptr) {
        *kind_out = kind;
    }
    return timeout_ms;
}

static uint32_t connection_index(WorkerRuntime *rt, Connection *conn) {
    return static_cast<uint32_t>(conn - &rt->connections[0]);
}

static uint64_t make_listener_token() {
    return static_cast<uint64_t>(CoreTag::Listener) << 56;
}

static uint64_t make_conn_token(CoreTag::Kind kind, uint32_t generation, uint32_t index) {
    return (static_cast<uint64_t>(kind) << 56) |
           ((static_cast<uint64_t>(generation) & 0x0FFFFFFFu) << 28) |
           (static_cast<uint64_t>(index) & 0x0FFFFFFFu);
}

static CoreTag::Kind token_kind(uint64_t token) {
    return static_cast<CoreTag::Kind>((token >> 56) & 0xFFu);
}

static uint32_t token_generation(uint64_t token) {
    return static_cast<uint32_t>((token >> 28) & 0x0FFFFFFFu);
}

static uint32_t token_index(uint64_t token) {
    return static_cast<uint32_t>(token & 0x0FFFFFFFu);
}

static uint32_t desired_client_events(const Connection *conn) {
    uint32_t events = platform::kEventEdge | platform::kEventReadHup;
    switch (conn->state) {
        case ConnState::ReadClientHeaders:
            events |= platform::kEventRead;
            break;
        case ConnState::WriteUpstream:
            if (conn->request_body_forwarded < conn->request_body_expected && conn->client_buffer.writable() > 0) {
                events |= platform::kEventRead;
            }
            break;
        case ConnState::WriteClient:
            if (!conn->client_buffer.empty() || !conn->upstream_buffer.empty()) {
                events |= platform::kEventWrite;
            }
            break;
        case ConnState::SpliceResponseBody:
            if (conn->pipe_buffered_bytes > 0) {
                events |= platform::kEventWrite;
            }
            break;
        default:
            break;
    }
    return events;
}

static uint32_t desired_upstream_events(const Connection *conn) {
    uint32_t events = platform::kEventEdge | platform::kEventReadHup;
    switch (conn->state) {
        case ConnState::ConnectUpstream:
        case ConnState::WriteUpstream:
            events |= platform::kEventWrite;
            break;
        case ConnState::ReadUpstream:
            if (conn->upstream_buffer.writable() > 0) {
                events |= platform::kEventRead;
            }
            break;
        case ConnState::SpliceResponseBody:
            if (conn->remaining_bytes > 0 && conn->pipe_buffered_bytes < conn->pipe_capacity_bytes) {
                events |= platform::kEventRead;
            }
            break;
        default:
            break;
    }
    return events;
}

static bool loop_add(WorkerRuntime *rt, int fd, uint32_t events, uint64_t token) {
    std::string error;
    return rt->loop->Add(fd, events, token, &error);
}

static bool loop_mod(WorkerRuntime *rt, int fd, uint32_t events, uint64_t token) {
    std::string error;
    return rt->loop->Modify(fd, events, token, &error);
}

static void loop_del(WorkerRuntime *rt, int fd) {
    rt->loop->Remove(fd);
}

static bool refresh_client_interest(WorkerRuntime *rt, Connection *conn);
static bool refresh_upstream_interest(WorkerRuntime *rt, Connection *conn);
static bool finish_response(WorkerRuntime *rt, Connection *conn);
static bool handle_upstream_write(WorkerRuntime *rt, Connection *conn);
static bool handle_upstream_read(WorkerRuntime *rt, Connection *conn);
static bool handle_splice_response_body(WorkerRuntime *rt, Connection *conn);
static bool handle_client_write(WorkerRuntime *rt, Connection *conn);
static bool handle_connection_timeout(WorkerRuntime *rt, Connection *conn, TimeoutKind kind, uint64_t now);

static bool arm_error_response(WorkerRuntime *rt, Connection *conn) {
    ++rt->total_errors;
    conn->state = ConnState::WriteClient;
    return refresh_client_interest(rt, conn) && refresh_upstream_interest(rt, conn);
}

static void release_connection(WorkerRuntime *rt, Connection *conn) {
    assert(conn != nullptr);
    if (!conn->in_use && conn->client_fd < 0 && conn->upstream_fd < 0) {
        return;
    }
    if (conn->pipefd[0] >= 0) {
        close_fd(conn->pipefd[0]);
    }
    if (conn->pipefd[1] >= 0) {
        close_fd(conn->pipefd[1]);
    }
    conn->pipe_initialized = false;
    if (conn->client_fd >= 0) {
        if (conn->client_registered) {
            loop_del(rt, conn->client_fd);
            conn->client_registered = false;
            conn->client_token_generation = 0;
        }
        close_fd(conn->client_fd);
    }
    if (conn->upstream_fd >= 0) {
        if (conn->upstream_registered) {
            loop_del(rt, conn->upstream_fd);
            conn->upstream_registered = false;
            conn->upstream_token_generation = 0;
        }
        close_fd(conn->upstream_fd);
    }
    const uint32_t idx = static_cast<uint32_t>(conn - &rt->connections[0]);
    conn->Reset(-1);
    rt->free_list.push_back(idx);
    if (rt->active_connections > 0) {
        --rt->active_connections;
    }
}

static bool refresh_client_interest(WorkerRuntime *rt, Connection *conn) {
    if (conn->client_fd < 0 || !conn->client_registered) {
        return true;
    }
    const uint32_t events = desired_client_events(conn);
    if (events == conn->client_events && conn->client_token_generation == conn->generation) {
        return true;
    }
    if (!loop_mod(rt, conn->client_fd, events,
                  make_conn_token(CoreTag::Client, conn->generation, connection_index(rt, conn)))) {
        return false;
    }
    conn->client_events = events;
    conn->client_token_generation = conn->generation;
    return true;
}

static bool refresh_upstream_interest(WorkerRuntime *rt, Connection *conn) {
    if (conn->upstream_fd < 0 || !conn->upstream_registered) {
        return true;
    }
    const uint32_t events = desired_upstream_events(conn);
    if (events == conn->upstream_events && conn->upstream_token_generation == conn->generation) {
        return true;
    }
    if (!loop_mod(rt, conn->upstream_fd, events,
                  make_conn_token(CoreTag::Upstream, conn->generation, connection_index(rt, conn)))) {
        return false;
    }
    conn->upstream_events = events;
    conn->upstream_token_generation = conn->generation;
    return true;
}

static void close_upstream_side(WorkerRuntime *rt, Connection *conn) {
    if (conn->upstream_fd >= 0) {
        if (conn->upstream_registered) {
            loop_del(rt, conn->upstream_fd);
            conn->upstream_registered = false;
            conn->upstream_token_generation = 0;
        }
        close_fd(conn->upstream_fd);
        conn->upstream_events = 0;
    }
}

static WorkerRuntime::PoolKey pool_key_for(const UpstreamTarget *target) {
    WorkerRuntime::PoolKey key;
    key.host_hash = target != nullptr ? target->host_hash : 0;
    key.port = target != nullptr ? target->port : 0;
    key.tls = (target != nullptr && target->use_tls) ? 1 : 0;
    return key;
}

static bool pooled_socket_healthy(int fd) {
    if (fd < 0) {
        return false;
    }
    int so_error = 0;
    socklen_t so_error_len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) < 0 || so_error != 0) {
        return false;
    }

    struct pollfd pfd;
    std::memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLERR | POLLHUP;
#ifdef POLLRDHUP
    pfd.events |= POLLRDHUP;
#endif
    const int poll_rc = poll(&pfd, 1, 0);
    if (poll_rc < 0) {
        return false;
    }
    if (poll_rc > 0 && (pfd.revents & (POLLERR | POLLHUP
#ifdef POLLRDHUP
        | POLLRDHUP
#endif
        | POLLNVAL | POLLIN)) != 0) {
        return false;
    }

    char probe = 0;
    for (;;) {
        const ssize_t n = recv(fd, &probe, sizeof(probe), MSG_PEEK | MSG_DONTWAIT);
        if (n == 0) {
            return false;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno == EAGAIN || errno == EWOULDBLOCK;
        }
        return false;
    }
}

static int acquire_upstream_from_pool(WorkerRuntime *rt, const UpstreamTarget *target) {
    if (rt == nullptr || target == nullptr) {
        return -1;
    }
    const WorkerRuntime::PoolKey key = pool_key_for(target);
    std::unordered_map<WorkerRuntime::PoolKey, std::deque<WorkerRuntime::PooledUpstream>, WorkerRuntime::PoolKeyHash>::iterator it =
        rt->upstream_pool.find(key);
    if (it == rt->upstream_pool.end()) {
        return -1;
    }
    std::deque<WorkerRuntime::PooledUpstream> &bucket = it->second;
    while (!bucket.empty()) {
        const WorkerRuntime::PooledUpstream pooled = bucket.back();
        bucket.pop_back();
        if (pooled.fd < 0) {
            continue;
        }
        if (!pooled_socket_healthy(pooled.fd)) {
            int doomed = pooled.fd;
            close_fd(doomed);
            continue;
        }
        if (bucket.empty()) {
            rt->upstream_pool.erase(it);
        }
        return pooled.fd;
    }
    rt->upstream_pool.erase(it);
    return -1;
}

static void recycle_upstream_side(WorkerRuntime *rt, Connection *conn) {
    if (conn->upstream_fd < 0) {
        return;
    }
    int reusable = conn->upstream_fd;
    if (conn->upstream_registered) {
        loop_del(rt, reusable);
        conn->upstream_registered = false;
        conn->upstream_token_generation = 0;
    }
    conn->upstream_fd = -1;
    conn->upstream_events = 0;
    if (!conn->safe_upstream_keep_alive || conn->upstream_target == nullptr || !pooled_socket_healthy(reusable)) {
        close_fd(reusable);
        return;
    }
    WorkerRuntime::PoolKey key = pool_key_for(conn->upstream_target);
    std::deque<WorkerRuntime::PooledUpstream> &bucket = rt->upstream_pool[key];
    bucket.push_back(WorkerRuntime::PooledUpstream(reusable, now_ms()));
    while (bucket.size() > kMaxIdleUpstreamsPerKey) {
        int doomed = bucket.front().fd;
        bucket.pop_front();
        close_fd(doomed);
    }
}

static void reap_stale_upstream_pool(WorkerRuntime *rt, uint64_t now) {
    for (std::unordered_map<WorkerRuntime::PoolKey, std::deque<WorkerRuntime::PooledUpstream>, WorkerRuntime::PoolKeyHash>::iterator it =
             rt->upstream_pool.begin();
         it != rt->upstream_pool.end();) {
        std::deque<WorkerRuntime::PooledUpstream> &bucket = it->second;
        while (!bucket.empty()) {
            const WorkerRuntime::PooledUpstream &entry = bucket.front();
            if (entry.last_used_ms > 0 && (now - entry.last_used_ms) > kUpstreamPoolIdleTimeoutMs) {
                int doomed = entry.fd;
                close_fd(doomed);
                bucket.pop_front();
                continue;
            }
            break;
        }
        while (!bucket.empty()) {
            const WorkerRuntime::PooledUpstream &entry = bucket.back();
            if (entry.last_used_ms > 0 && (now - entry.last_used_ms) > kUpstreamPoolIdleTimeoutMs) {
                int doomed = entry.fd;
                close_fd(doomed);
                bucket.pop_back();
                continue;
            }
            break;
        }
        if (bucket.empty()) {
            it = rt->upstream_pool.erase(it);
            continue;
        }
        ++it;
    }
}

static void queue_error_response(Connection *conn, int status, const char *message, bool close_after) {
    conn->client_buffer.clear();
    conn->safe_upstream_keep_alive = false;
    conn->splice_enabled = false;
    conn->splice_eof = false;
    conn->remaining_bytes = 0;
    conn->pipe_buffered_bytes = 0;
    conn->passthrough_response_headers = false;
    conn->response_header_bytes = 0;
    conn->response_header_forwarded = 0;
    char header[512];
    const char *status_text = "Bad Request";
    switch (status) {
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        case 408: status_text = "Request Timeout"; break;
        case 413: status_text = "Payload Too Large"; break;
        case 500: status_text = "Internal Server Error"; break;
        case 501: status_text = "Not Implemented"; break;
        case 502: status_text = "Bad Gateway"; break;
        case 503: status_text = "Service Unavailable"; break;
        case 504: status_text = "Gateway Timeout"; break;
        default: break;
    }
    const int len = std::snprintf(header, sizeof(header),
                                  "HTTP/1.1 %d %s\r\n"
                                  "Content-Type: text/plain; charset=utf-8\r\n"
                                  "Content-Length: %zu\r\n"
                                  "Connection: %s\r\n\r\n%s",
                                  status,
                                  status_text,
                                  std::strlen(message),
                                  close_after ? "close" : "keep-alive",
                                  message);
    append_bytes(conn->client_buffer, header, static_cast<std::size_t>(len));
    conn->state = ConnState::WriteClient;
    conn->close_after_response = close_after;
    conn->safe_client_keep_alive = !close_after;
    conn->response_parsed = true;
    conn->response.no_body = true;
    conn->response_body_expected = 0;
    conn->response_body_forwarded = 0;
}

static void append_target_path(FixedBuffer<32768> &buffer,
                               const UpstreamTarget *target,
                               const RequestHead &request,
                               const char *request_buffer) {
    const std::string &base = target->base_path;
    const char *req_path = request_buffer + request.path_off;

    if (base.empty()) {
        append_literal(buffer, "/");
    } else {
        append_bytes(buffer, base.data(), base.size());
    }

    if (request.path_len > 0) {
        const bool base_has_slash = !base.empty() && base[base.size() - 1] == '/';
        const bool req_has_slash = req_path[0] == '/';
        if (base_has_slash && req_has_slash) {
            append_bytes(buffer, req_path + 1, request.path_len - 1);
        } else if (!base_has_slash && !req_has_slash) {
            append_literal(buffer, "/");
            append_bytes(buffer, req_path, request.path_len);
        } else {
            append_bytes(buffer, req_path, request.path_len);
        }
    }

    if (request.query_len > 0) {
        append_literal(buffer, "?");
        append_bytes(buffer, request_buffer + request.query_off, request.query_len);
    }
}

static bool build_upstream_request(Connection *conn, std::string *error_out) {
    conn->upstream_buffer.clear();
    const char *request_buffer = conn->client_buffer.data();

    append_bytes(conn->upstream_buffer, request_buffer + conn->request.method_off, conn->request.method_len);
    append_literal(conn->upstream_buffer, " ");
    append_target_path(conn->upstream_buffer, conn->upstream_target, conn->request, request_buffer);
    append_literal(conn->upstream_buffer, " HTTP/1.1\r\nHost: ");
    append_bytes(conn->upstream_buffer, conn->upstream_target->host.data(), conn->upstream_target->host.size());
    append_literal(conn->upstream_buffer, ":");
    append_uint(conn->upstream_buffer, conn->upstream_target->port);
    append_literal(conn->upstream_buffer, "\r\nConnection: keep-alive\r\n");

    for (uint16_t i = 0; i < conn->request.header_count; ++i) {
        const HeaderRef &header = conn->request_headers[i];
        if (HeaderEquals(request_buffer, header, "Host") || is_hop_header(request_buffer, header)) {
            continue;
        }
        append_bytes(conn->upstream_buffer, request_buffer + header.name_off, header.name_len);
        append_literal(conn->upstream_buffer, ": ");
        append_bytes(conn->upstream_buffer, request_buffer + header.value_off, header.value_len);
        append_literal(conn->upstream_buffer, "\r\n");
    }

    if (!conn->request.has_content_length && conn->request_body_expected > 0) {
        append_literal(conn->upstream_buffer, "Content-Length: ");
        append_uint(conn->upstream_buffer, conn->request_body_expected);
        append_literal(conn->upstream_buffer, "\r\n");
    }
    append_literal(conn->upstream_buffer, "\r\n");

    const std::size_t body_offset = conn->request.headers_end;
    const std::size_t body_available = conn->client_buffer.end > body_offset ? (conn->client_buffer.end - body_offset) : 0;
    std::size_t to_copy = body_available;
    if (to_copy > conn->upstream_buffer.writable()) {
        to_copy = conn->upstream_buffer.writable();
    }
    if (to_copy > conn->request_body_expected) {
        to_copy = static_cast<std::size_t>(conn->request_body_expected);
    }
    if (to_copy > 0) {
        append_bytes(conn->upstream_buffer, conn->client_buffer.data() + body_offset, to_copy);
    }
    conn->request_body_forwarded = to_copy;

    if (body_available > to_copy) {
        const std::size_t remain = body_available - to_copy;
        if (remain > 0) {
            std::memmove(conn->client_buffer.data(), request_buffer + body_offset + to_copy, remain);
            conn->client_buffer.end = remain;
        }
    } else {
        conn->client_buffer.clear();
    }
    conn->pipelined_bytes = conn->client_buffer.end > (conn->request_body_expected - conn->request_body_forwarded);

    if (conn->upstream_buffer.empty()) {
        if (error_out != nullptr) {
            *error_out = "failed to build upstream request";
        }
        return false;
    }
    return true;
}

static bool route_request(WorkerRuntime *rt, Connection *conn) {
    const RouteSnapshotEntry *route = rt->snapshot.Match(conn->client_buffer.data() + conn->request.method_off,
                                                         conn->request.method_len,
                                                         conn->client_buffer.data() + conn->request.path_off,
                                                         conn->request.path_len);
    if (route == nullptr) {
        queue_error_response(conn, 404, "Not Found", true);
        return false;
    }
    conn->route = route;
    if (!rt->snapshot.Resolve(route, &conn->upstream_target) || conn->upstream_target == nullptr) {
        queue_error_response(conn, 502, "Service not available", true);
        return false;
    }
    if (!conn->upstream_target->address_ready) {
        queue_error_response(conn, 502, "Upstream address unavailable", true);
        return false;
    }
    return true;
}

static bool flush_iov(int fd,
                      FixedBuffer<32768> *first,
                      FixedBuffer<32768> *second,
                      bool *blocked,
                      std::size_t *bytes_written_out) {
    struct iovec iov[2];
    int iovcnt = 0;
    if (first != nullptr && !first->empty()) {
        iov[iovcnt].iov_base = const_cast<char *>(first->read_ptr());
        iov[iovcnt].iov_len = first->readable();
        ++iovcnt;
    }
    if (second != nullptr && !second->empty()) {
        iov[iovcnt].iov_base = const_cast<char *>(second->read_ptr());
        iov[iovcnt].iov_len = second->readable();
        ++iovcnt;
    }
    if (iovcnt == 0) {
        return true;
    }
    std::size_t total_written = 0;
    for (;;) {
        const ssize_t written = writev(fd, iov, iovcnt);
        if (written > 0) {
            total_written += static_cast<std::size_t>(written);
            std::size_t remain = static_cast<std::size_t>(written);
            if (first != nullptr && !first->empty()) {
                const std::size_t take = std::min(remain, first->readable());
                first->consumed(take);
                remain -= take;
            }
            if (remain > 0 && second != nullptr && !second->empty()) {
                second->consumed(remain);
            }
            if ((first == nullptr || first->empty()) && (second == nullptr || second->empty())) {
                if (bytes_written_out != nullptr) {
                    *bytes_written_out += total_written;
                }
                return true;
            }
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (bytes_written_out != nullptr) {
                *bytes_written_out += total_written;
            }
            if (blocked != nullptr) {
                *blocked = true;
            }
            return true;
        }
        return false;
    }
}

static bool read_into_buffer(int fd, FixedBuffer<32768> *buffer, bool *saw_eof, std::size_t *bytes_read_out) {
    std::size_t total_read = 0;
    for (;;) {
        buffer->compact_if_needed();
        if (unlikely(buffer->writable() == 0)) {
            if (bytes_read_out != nullptr) {
                *bytes_read_out += total_read;
            }
            return true;
        }
        const ssize_t n = recv(fd, buffer->write_ptr(), buffer->writable(), 0);
        if (likely(n > 0)) {
            buffer->produced(static_cast<std::size_t>(n));
            total_read += static_cast<std::size_t>(n);
            continue;
        }
        if (n == 0) {
            if (bytes_read_out != nullptr) {
                *bytes_read_out += total_read;
            }
            if (saw_eof != nullptr) {
                *saw_eof = true;
            }
            return true;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (bytes_read_out != nullptr) {
                *bytes_read_out += total_read;
            }
            return true;
        }
        return false;
    }
}

static bool open_upstream(WorkerRuntime *rt, Connection *conn) {
    int fd = acquire_upstream_from_pool(rt, conn->upstream_target);
    if (fd >= 0) {
        conn->upstream_fd = fd;
        conn->upstream_connected = true;
        conn->state = ConnState::WriteUpstream;
        conn->last_progress_ms = now_ms();
        const uint32_t events = desired_upstream_events(conn);
        if (!loop_add(rt, conn->upstream_fd, events,
                      make_conn_token(CoreTag::Upstream, conn->generation, connection_index(rt, conn)))) {
            close_fd(conn->upstream_fd);
            queue_error_response(conn, 502, "Upstream reuse failed", true);
            return false;
        }
        conn->upstream_registered = true;
        conn->upstream_events = events;
        conn->upstream_token_generation = conn->generation;
        return handle_upstream_write(rt, conn);
    }

    fd = socket(conn->upstream_target->address.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        queue_error_response(conn, 502, "Upstream connect failed", true);
        return false;
    }
    std::string err;
    if (!set_nonblocking(fd, &err)) {
        close_fd(fd);
        queue_error_response(conn, 502, "Upstream connect failed", true);
        return false;
    }
    if (!suppress_sigpipe(fd, &err)) {
        close_fd(fd);
        queue_error_response(conn, 502, "Upstream connect failed", true);
        return false;
    }
    set_tcp_nodelay(fd);
    const int rc = connect(fd,
                           reinterpret_cast<const struct sockaddr *>(&conn->upstream_target->address),
                           conn->upstream_target->address_len);
    if (rc < 0 && errno != EINPROGRESS) {
        close_fd(fd);
        queue_error_response(conn, 502, "Upstream connect failed", true);
        return false;
    }
    conn->upstream_fd = fd;
    conn->state = ConnState::ConnectUpstream;
    conn->last_progress_ms = now_ms();
    const uint32_t events = desired_upstream_events(conn);
    if (!loop_add(rt, conn->upstream_fd, events,
                  make_conn_token(CoreTag::Upstream, conn->generation, connection_index(rt, conn)))) {
        close_fd(conn->upstream_fd);
        queue_error_response(conn, 502, "Upstream connect failed", true);
        return false;
    }
    conn->upstream_registered = true;
    conn->upstream_events = events;
    conn->upstream_token_generation = conn->generation;
    if (rc == 0) {
        conn->upstream_connected = true;
        conn->state = ConnState::WriteUpstream;
        conn->last_progress_ms = now_ms();
        return handle_upstream_write(rt, conn);
    }
    return true;
}

static bool handle_client_header_read(WorkerRuntime *rt, Connection *conn) {
    std::size_t bytes_read = 0;
    if (!read_into_buffer(conn->client_fd, &conn->client_buffer, &conn->saw_client_eof, &bytes_read)) {
        return false;
    }
    if (bytes_read > 0) {
        mark_progress(conn, now_ms());
    }
    if (unlikely(conn->saw_client_eof && conn->client_buffer.empty())) {
        return false;
    }

    const char *error = nullptr;
    const ParseStatus status = ParseRequestHead(conn->client_buffer.data(), conn->client_buffer.end,
                                                &conn->request, conn->request_headers, 64, &error);
    if (status == ParseStatus::NeedMore) {
        if (conn->saw_client_eof) {
            return false;
        }
        return true;
    }
    if (status == ParseStatus::Error) {
        queue_error_response(conn,
                             request_error_is_too_large(error) ? 413 : 400,
                             error != nullptr ? error : "invalid request",
                             true);
        return arm_error_response(rt, conn);
    }

    if (conn->request.chunked) {
        queue_error_response(conn, 501, "chunked request bodies are not supported", true);
        return arm_error_response(rt, conn);
    }
    if (rt->max_body_bytes > 0 && conn->request.content_length > rt->max_body_bytes) {
        queue_error_response(conn, 413, "payload too large", true);
        return arm_error_response(rt, conn);
    }

    conn->request_parsed = true;
    ++rt->total_requests;
    conn->client_keep_alive = conn->request.keep_alive;
    conn->request_body_expected = conn->request.has_content_length ? conn->request.content_length : 0;
    conn->request.no_body = conn->request_body_expected == 0;

    if (!route_request(rt, conn)) {
        return arm_error_response(rt, conn);
    }
    std::string err;
    if (!build_upstream_request(conn, &err)) {
        queue_error_response(conn, 500, err.empty() ? "failed to build upstream request" : err.c_str(), true);
        return arm_error_response(rt, conn);
    }
    return open_upstream(rt, conn);
}

static bool handle_upstream_connect(WorkerRuntime *rt, Connection *conn) {
    int so_error = 0;
    socklen_t so_error_len = sizeof(so_error);
    if (getsockopt(conn->upstream_fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) < 0 || so_error != 0) {
        queue_error_response(conn, 502, "upstream connect failed", true);
        return arm_error_response(rt, conn);
    }
    conn->upstream_connected = true;
    conn->state = ConnState::WriteUpstream;
    mark_progress(conn, now_ms());
    if (!refresh_upstream_interest(rt, conn) || !refresh_client_interest(rt, conn)) {
        return false;
    }
    return handle_upstream_write(rt, conn);
}

static bool handle_upstream_write(WorkerRuntime *rt, Connection *conn) {
    for (;;) {
        bool blocked = false;
        const std::size_t request_body_before = conn->client_buffer.readable();
        std::size_t bytes_written = 0;
        if (!flush_iov(conn->upstream_fd, &conn->upstream_buffer, &conn->client_buffer, &blocked, &bytes_written)) {
            queue_error_response(conn, 502, "upstream write failed", true);
            return arm_error_response(rt, conn);
        }
        const std::size_t request_body_after = conn->client_buffer.readable();
        const std::size_t body_forwarded_now =
            request_body_before >= request_body_after ? (request_body_before - request_body_after) : 0;
        if (request_body_before >= request_body_after) {
            conn->request_body_forwarded += static_cast<uint64_t>(body_forwarded_now);
            if (conn->request_body_forwarded > conn->request_body_expected) {
                conn->request_body_forwarded = conn->request_body_expected;
            }
        }
        if (conn->request_body_forwarded >= conn->request_body_expected) {
            if (bytes_written > 0) {
                mark_progress(conn, now_ms());
            }
        } else if (body_forwarded_now > 0) {
            mark_progress(conn, now_ms());
        }

        bool body_read_progress = false;
        while (conn->request_body_forwarded < conn->request_body_expected && conn->client_buffer.empty()) {
            const uint64_t remain = conn->request_body_expected - conn->request_body_forwarded;
            conn->client_buffer.compact_if_needed();
            const std::size_t want = static_cast<std::size_t>(std::min<uint64_t>(conn->client_buffer.writable(), remain));
            if (want == 0) {
                break;
            }
            const ssize_t n = recv(conn->client_fd, conn->client_buffer.write_ptr(), want, 0);
            if (n > 0) {
                conn->client_buffer.produced(static_cast<std::size_t>(n));
                body_read_progress = true;
                continue;
            }
            if (n == 0) {
                queue_error_response(conn, 400, "client closed request body early", true);
                return arm_error_response(rt, conn);
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            queue_error_response(conn, 400, "client read failed", true);
            return arm_error_response(rt, conn);
        }
        if (body_read_progress) {
            mark_progress(conn, now_ms());
            if (!blocked) {
                continue;
            }
        }

        if (conn->upstream_buffer.empty() && conn->client_buffer.empty() &&
            conn->request_body_forwarded >= conn->request_body_expected) {
            conn->state = ConnState::ReadUpstream;
        }
        if (!refresh_client_interest(rt, conn) || !refresh_upstream_interest(rt, conn)) {
            return false;
        }
        if (conn->state == ConnState::ReadUpstream) {
            return handle_upstream_read(rt, conn);
        }
        return true;
    }
}

static bool build_client_response_header(Connection *conn) {
    conn->client_buffer.clear();
    const char *resp = conn->upstream_buffer.data();
    char status_line[512];
    int line_len = std::snprintf(status_line, sizeof(status_line), "HTTP/1.1 %u %.*s\r\n",
                                 static_cast<unsigned>(conn->response.status_code),
                                 static_cast<int>(conn->response.reason_len),
                                 resp + conn->response.reason_off);
    append_bytes(conn->client_buffer, status_line, static_cast<std::size_t>(line_len));

    for (uint16_t i = 0; i < conn->response.header_count; ++i) {
        const HeaderRef &header = conn->response_headers[i];
        if (HeaderEquals(resp, header, "Connection")) {
            continue;
        }
        append_bytes(conn->client_buffer, resp + header.name_off, header.name_len);
        append_literal(conn->client_buffer, ": ");
        append_bytes(conn->client_buffer, resp + header.value_off, header.value_len);
        append_literal(conn->client_buffer, "\r\n");
    }
    if (!conn->response.has_content_length && conn->response.no_body) {
        append_literal(conn->client_buffer, "Content-Length: 0\r\n");
    }
    append_literal(conn->client_buffer,
                   conn->safe_client_keep_alive ? "Connection: keep-alive\r\n\r\n"
                                                : "Connection: close\r\n\r\n");
    return true;
}

static bool ensure_splice_pipe(Connection *conn) {
#ifdef __linux__
    if (conn->pipe_initialized && conn->pipefd[0] >= 0 && conn->pipefd[1] >= 0) {
        return true;
    }
    int pipefd[2];
#ifdef O_CLOEXEC
    if (pipe2(pipefd, O_NONBLOCK | O_CLOEXEC) != 0) {
        return false;
    }
#else
    if (pipe(pipefd) != 0) {
        return false;
    }
    if (fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK) != 0 ||
        fcntl(pipefd[1], F_SETFL, fcntl(pipefd[1], F_GETFL, 0) | O_NONBLOCK) != 0) {
        close_fd(pipefd[0]);
        close_fd(pipefd[1]);
        return false;
    }
#endif
    conn->pipefd[0] = pipefd[0];
    conn->pipefd[1] = pipefd[1];
    conn->pipe_initialized = true;
    conn->pipe_buffered_bytes = 0;
    int pipe_size = 0;
#ifdef F_GETPIPE_SZ
    pipe_size = fcntl(conn->pipefd[0], F_GETPIPE_SZ);
#endif
    conn->pipe_capacity_bytes = pipe_size > 0 ? static_cast<uint32_t>(pipe_size) : 65536u;
    return true;
#else
    (void) conn;
    return false;
#endif
}

static bool can_passthrough_response_headers(const Connection *conn) {
    (void) conn;
    return false;
}

static bool can_splice_response_body(WorkerRuntime *rt, const Connection *conn) {
    if (!rt->loop->SupportsSplice()) {
        return false;
    }
    if (conn->response.version_len != 8) {
        return false;
    }
    const char *response_buffer = conn->upstream_buffer.data();
    if (std::memcmp(response_buffer + conn->response.version_off, "HTTP/1.1", 8) != 0) {
        return false;
    }
    if (!conn->response.has_content_length || conn->response.no_body) {
        return false;
    }
    if (conn->response.chunked || conn->response.close_delimited) {
        return false;
    }
    if (conn->response.content_length < 8192) {
        return false;
    }
    return true;
}

static bool handle_upstream_read(WorkerRuntime *rt, Connection *conn) {
    std::size_t bytes_read = 0;
    if (!read_into_buffer(conn->upstream_fd, &conn->upstream_buffer, &conn->saw_upstream_eof, &bytes_read)) {
        queue_error_response(conn, 502, "upstream read failed", true);
        return arm_error_response(rt, conn);
    }
    if (bytes_read > 0) {
        mark_progress(conn, now_ms());
    }
    if (!conn->response_parsed) {
        const char *error = nullptr;
        const ParseStatus status = ParseResponseHead(conn->upstream_buffer.data(), conn->upstream_buffer.end,
                                                     &conn->response, conn->response_headers, 64, &error);
        if (status == ParseStatus::NeedMore) {
            if (conn->saw_upstream_eof) {
                queue_error_response(conn, 502, "upstream closed before response headers completed", true);
                return arm_error_response(rt, conn);
            }
            return refresh_upstream_interest(rt, conn);
        }
        if (status == ParseStatus::Error) {
            queue_error_response(conn, 502, error != nullptr ? error : "invalid upstream response", true);
            return arm_error_response(rt, conn);
        }
        conn->response_parsed = true;
        conn->response_body_expected = conn->response.has_content_length ? conn->response.content_length : 0;
        conn->safe_upstream_keep_alive =
            conn->response.keep_alive &&
            (conn->response.has_content_length || conn->response.no_body) &&
            !conn->response.chunked &&
            !conn->response.close_delimited;
        conn->safe_client_keep_alive =
            conn->client_keep_alive &&
            !conn->pipelined_bytes &&
            (conn->response.has_content_length || conn->response.no_body) &&
            !conn->response.chunked &&
            !conn->response.close_delimited;
        conn->close_after_response = !conn->safe_client_keep_alive;
        conn->splice_enabled = can_splice_response_body(rt, conn);
        conn->remaining_bytes = conn->response_body_expected;
        conn->splice_eof = false;
        conn->pipe_buffered_bytes = 0;
        conn->passthrough_response_headers = can_passthrough_response_headers(conn);
        if (conn->passthrough_response_headers) {
            ++rt->header_passthrough_hits;
        }
        if (conn->splice_enabled) {
            ++rt->splice_hits;
        }
        conn->response_header_bytes = conn->response.headers_end;
        conn->response_header_forwarded = 0;
        if (conn->passthrough_response_headers) {
            conn->client_buffer.clear();
        } else {
            build_client_response_header(conn);
            conn->upstream_buffer.start = conn->response.headers_end;
            if (conn->upstream_buffer.start > conn->upstream_buffer.end) {
                conn->upstream_buffer.start = conn->upstream_buffer.end;
            }
        }
        conn->state = ConnState::WriteClient;
        if (!refresh_client_interest(rt, conn) || !refresh_upstream_interest(rt, conn)) {
            return false;
        }
        return handle_client_write(rt, conn);
    }

    if (!conn->upstream_buffer.empty()) {
        conn->state = ConnState::WriteClient;
        if (!refresh_client_interest(rt, conn) || !refresh_upstream_interest(rt, conn)) {
            return false;
        }
        return handle_client_write(rt, conn);
    }
    if (conn->saw_upstream_eof) {
        conn->safe_upstream_keep_alive = false;
        const uint64_t buffered_body = static_cast<uint64_t>(conn->upstream_buffer.readable());
        const uint64_t completed_body = conn->response_body_forwarded + buffered_body;
        const bool body_complete =
            conn->response.no_body ||
            conn->response.close_delimited ||
            (conn->response.has_content_length && completed_body >= conn->response_body_expected);
        if (!body_complete) {
            if (!response_started_to_client(conn)) {
                queue_error_response(conn, 502, "upstream closed before response body completed", true);
                return arm_error_response(rt, conn);
            }
            return false;
        }
        close_upstream_side(rt, conn);
        if (conn->client_buffer.empty() && conn->upstream_buffer.empty()) {
            return conn->safe_client_keep_alive ? finish_response(rt, conn) : (release_connection(rt, conn), true);
        }
        conn->state = ConnState::WriteClient;
        return refresh_client_interest(rt, conn);
    }
    return true;
}

static bool handle_splice_response_body(WorkerRuntime *rt, Connection *conn) {
    if (!conn->splice_enabled) {
        conn->state = ConnState::ReadUpstream;
        if (!refresh_client_interest(rt, conn) || !refresh_upstream_interest(rt, conn)) {
            return false;
        }
        return handle_upstream_read(rt, conn);
    }
    if (!ensure_splice_pipe(conn)) {
        conn->splice_enabled = false;
        conn->state = ConnState::ReadUpstream;
        if (!refresh_client_interest(rt, conn) || !refresh_upstream_interest(rt, conn)) {
            return false;
        }
        return handle_upstream_read(rt, conn);
    }

#ifdef __linux__
    static const std::size_t kSpliceChunk = 64 * 1024;
    bool splice_progress = false;
    const uint64_t now = now_ms();

    for (;;) {
        if (conn->pipe_buffered_bytes > 0) {
            const ssize_t moved = splice(conn->pipefd[0], nullptr, conn->client_fd, nullptr,
                                         conn->pipe_buffered_bytes, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (moved > 0) {
                splice_progress = true;
                conn->response_started = true;
                conn->pipe_buffered_bytes -= static_cast<uint32_t>(moved);
                conn->response_body_forwarded += static_cast<uint64_t>(moved);
                if (conn->remaining_bytes >= static_cast<uint64_t>(moved)) {
                    conn->remaining_bytes -= static_cast<uint64_t>(moved);
                } else {
                    conn->remaining_bytes = 0;
                }
                if (conn->remaining_bytes == 0 && conn->pipe_buffered_bytes == 0) {
                    return finish_response(rt, conn);
                }
                continue;
            }
            if (moved < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }
            return false;
        }

        if (conn->remaining_bytes == 0) {
            return finish_response(rt, conn);
        }
        if (conn->pipe_buffered_bytes >= conn->pipe_capacity_bytes) {
            break;
        }
        const uint64_t pipe_room = static_cast<uint64_t>(conn->pipe_capacity_bytes - conn->pipe_buffered_bytes);
        const std::size_t want = static_cast<std::size_t>(std::min<uint64_t>(
            conn->remaining_bytes, std::min<uint64_t>(static_cast<uint64_t>(kSpliceChunk), pipe_room)));
        if (want == 0) {
            break;
        }
        const ssize_t moved_in = splice(conn->upstream_fd, nullptr, conn->pipefd[1], nullptr, want,
                                        SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (moved_in > 0) {
            splice_progress = true;
            conn->pipe_buffered_bytes += static_cast<uint32_t>(moved_in);
            continue;
        }
        if (moved_in == 0) {
            conn->splice_eof = true;
            return false;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        if ((errno == EINVAL || errno == ENOSYS) && conn->pipe_buffered_bytes == 0) {
            ++rt->splice_fallbacks;
            ++rt->fallback_hits;
            conn->splice_enabled = false;
            conn->state = ConnState::ReadUpstream;
            if (!refresh_client_interest(rt, conn) || !refresh_upstream_interest(rt, conn)) {
                return false;
            }
            return handle_upstream_read(rt, conn);
        }
        return false;
    }

    if (splice_progress) {
        mark_progress(conn, now);
    }
    conn->state = ConnState::SpliceResponseBody;
    return refresh_client_interest(rt, conn) && refresh_upstream_interest(rt, conn);
#else
    (void) rt;
    conn->splice_enabled = false;
    conn->state = ConnState::ReadUpstream;
    return false;
#endif
}

static bool finish_response(WorkerRuntime *rt, Connection *conn) {
    recycle_upstream_side(rt, conn);
    if (conn->safe_client_keep_alive) {
        conn->ResetForNextRequest();
        conn->keep_alive_idle = true;
        conn->last_progress_ms = now_ms();
        if (!refresh_client_interest(rt, conn)) {
            return false;
        }
        return handle_client_header_read(rt, conn);
    }
    release_connection(rt, conn);
    return true;
}

static bool handle_client_write(WorkerRuntime *rt, Connection *conn) {
    bool blocked = false;
    const std::size_t body_before = conn->upstream_buffer.readable();
    std::size_t bytes_written = 0;
    if (!flush_iov(conn->client_fd, &conn->client_buffer, &conn->upstream_buffer, &blocked, &bytes_written)) {
        return false;
    }
    if (bytes_written > 0) {
        conn->response_started = true;
        mark_progress(conn, now_ms());
    }
    const std::size_t body_after = conn->upstream_buffer.readable();
    if (body_before >= body_after) {
        std::size_t upstream_forwarded = body_before - body_after;
        if (conn->passthrough_response_headers && upstream_forwarded > 0) {
            const std::size_t header_remaining =
                static_cast<std::size_t>(conn->response_header_bytes - conn->response_header_forwarded);
            const std::size_t header_sent = std::min(upstream_forwarded, header_remaining);
            conn->response_header_forwarded += static_cast<uint32_t>(header_sent);
            upstream_forwarded -= header_sent;
        }
        conn->response_body_forwarded += static_cast<uint64_t>(upstream_forwarded);
        if (conn->splice_enabled && conn->response_body_expected >= conn->response_body_forwarded) {
            conn->remaining_bytes = conn->response_body_expected - conn->response_body_forwarded;
        }
    }

    if (conn->response_parsed && conn->response.no_body && conn->client_buffer.empty() && conn->upstream_buffer.empty()) {
        return finish_response(rt, conn);
    }
    if (conn->response_parsed && conn->response.has_content_length && conn->client_buffer.empty() && conn->upstream_buffer.empty() && conn->response_body_forwarded >= conn->response_body_expected) {
        return finish_response(rt, conn);
    }
    if ((conn->response.chunked || conn->response.close_delimited) && conn->saw_upstream_eof && conn->client_buffer.empty() && conn->upstream_buffer.empty()) {
        release_connection(rt, conn);
        return true;
    }

    if (conn->client_buffer.empty() && conn->upstream_buffer.empty() && conn->response_parsed) {
        conn->state = (conn->splice_enabled && conn->remaining_bytes > 0)
                          ? ConnState::SpliceResponseBody
                          : ConnState::ReadUpstream;
    }
    if (!refresh_client_interest(rt, conn) || !refresh_upstream_interest(rt, conn)) {
        return false;
    }
    if (conn->state == ConnState::ReadUpstream) {
        return handle_upstream_read(rt, conn);
    }
    if (conn->state == ConnState::SpliceResponseBody) {
        return handle_splice_response_body(rt, conn);
    }
    return true;
}

static bool handle_connection_timeout(WorkerRuntime *rt, Connection *conn, TimeoutKind kind, uint64_t now) {
    ++rt->total_timeouts;
    conn->last_progress_ms = now;
    conn->keep_alive_idle = false;

    switch (kind) {
        case TimeoutKind::IdleKeepAlive:
            release_connection(rt, conn);
            return true;
        case TimeoutKind::ClientHeaders:
            queue_error_response(conn, 408, "request header timeout", true);
            return arm_error_response(rt, conn);
        case TimeoutKind::ClientBody:
            close_upstream_side(rt, conn);
            queue_error_response(conn, 408, "request body timeout", true);
            return arm_error_response(rt, conn);
        case TimeoutKind::UpstreamConnect:
        case TimeoutKind::UpstreamResponse:
            close_upstream_side(rt, conn);
            if (response_started_to_client(conn)) {
                release_connection(rt, conn);
                return true;
            }
            queue_error_response(conn, 504, "upstream timeout", true);
            return arm_error_response(rt, conn);
        case TimeoutKind::ClientWrite:
            release_connection(rt, conn);
            return true;
        case TimeoutKind::None:
        default:
            return true;
    }
}

static void reap_idle(WorkerRuntime *rt, uint64_t now) {
    reap_stale_upstream_pool(rt, now);
    for (std::size_t i = 0; i < rt->connections.size(); ++i) {
        Connection &conn = rt->connections[i];
        if (conn.client_fd < 0) {
            continue;
        }
        if (now <= conn.last_progress_ms) {
            continue;
        }
        TimeoutKind kind = TimeoutKind::None;
        const uint64_t timeout_ms = timeout_for_connection(&conn, &kind);
        if (timeout_ms == 0) {
            continue;
        }
        if (timeout_trace_enabled() &&
            (conn.state == ConnState::ReadUpstream || conn.state == ConnState::SpliceResponseBody)) {
            const uint64_t elapsed = now - conn.last_progress_ms;
            if (elapsed >= 25000ull) {
                std::fprintf(stderr,
                             "timeout-trace worker=%d state=%d elapsed=%llu timeout=%llu parsed=%d eof=%d client_fd=%d upstream_fd=%d\n",
                             rt->worker_index,
                             static_cast<int>(conn.state),
                             static_cast<unsigned long long>(elapsed),
                             static_cast<unsigned long long>(timeout_ms),
                             conn.response_parsed ? 1 : 0,
                             conn.saw_upstream_eof ? 1 : 0,
                             conn.client_fd,
                             conn.upstream_fd);
            }
        }
        if ((now - conn.last_progress_ms) > timeout_ms) {
            if (!handle_connection_timeout(rt, &conn, kind, now)) {
                release_connection(rt, &conn);
            }
        }
    }
}

static int accept_client_socket(int listen_fd) {
    sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
#ifdef __linux__
    int fd = accept4(listen_fd, reinterpret_cast<sockaddr *>(&addr), &addr_len, SOCK_NONBLOCK);
    return fd;
#else
    int fd = accept(listen_fd, reinterpret_cast<sockaddr *>(&addr), &addr_len);
    if (fd >= 0) {
        std::string ignored;
        if (!set_nonblocking(fd, &ignored) || !suppress_sigpipe(fd, &ignored)) {
            close_fd(fd);
            return -1;
        }
    }
    return fd;
#endif
}

static void cleanup_runtime(WorkerRuntime *rt) {
    if (rt == nullptr) {
        return;
    }
    for (std::size_t i = 0; i < rt->connections.size(); ++i) {
        if (rt->connections[i].client_fd >= 0) {
            release_connection(rt, &rt->connections[i]);
        }
    }
    for (std::unordered_map<WorkerRuntime::PoolKey, std::deque<WorkerRuntime::PooledUpstream>, WorkerRuntime::PoolKeyHash>::iterator it =
             rt->upstream_pool.begin();
         it != rt->upstream_pool.end();
         ++it) {
        std::deque<WorkerRuntime::PooledUpstream> &bucket = it->second;
        while (!bucket.empty()) {
            int fd = bucket.back().fd;
            bucket.pop_back();
            close_fd(fd);
        }
    }
    if (rt->listener_fd >= 0) {
        close_fd(rt->listener_fd);
    }
}

} // namespace

bool PrepareRouteSnapshot(RouteSnapshot *snapshot, std::string *error_out) {
    std::vector<RouteSnapshotEntry> &routes = snapshot->mutable_routes();
    for (std::size_t i = 0; i < routes.size(); ++i) {
        if (!routes[i].use_service) {
            routes[i].target.host_hash = fnv1a32(routes[i].target.host.data(), routes[i].target.host.size());
            if (!build_sockaddr(routes[i].target.host.c_str(), routes[i].target.port, &routes[i].target.address,
                                &routes[i].target.address_len, error_out)) {
                return false;
            }
            routes[i].target.address_ready = true;
        }
    }
    if (snapshot->has_fallback()) {
        RouteSnapshotEntry *fallback = snapshot->mutable_fallback();
        if (fallback != nullptr && !fallback->use_service) {
            fallback->target.host_hash = fnv1a32(fallback->target.host.data(), fallback->target.host.size());
            if (!build_sockaddr(fallback->target.host.c_str(), fallback->target.port, &fallback->target.address,
                                &fallback->target.address_len, error_out)) {
                return false;
            }
            fallback->target.address_ready = true;
        }
    }
    for (RouteSnapshot::service_iterator it = snapshot->services_begin(); it != snapshot->services_end(); ++it) {
        ServiceRegistryEntry &service = it->second;
        for (std::size_t target_idx = 0; target_idx < service.targets.size(); ++target_idx) {
            UpstreamTarget &target = service.targets[target_idx];
            target.host_hash = fnv1a32(target.host.data(), target.host.size());
            if (!build_sockaddr(target.host.c_str(), target.port, &target.address, &target.address_len, error_out)) {
                return false;
            }
            target.address_ready = true;
        }
    }
    return true;
}

ProxyEngine::ProxyEngine(ProxyEngineConfig config, std::unique_ptr<platform::EventLoop> loop)
    : config_(config), loop_(std::move(loop)), runtime_(new WorkerRuntime()) {}

ProxyEngine::~ProxyEngine() {
    cleanup_runtime(runtime_.get());
}

bool ProxyEngine::Initialize(std::string *error_out) {
    runtime_->loop = std::move(loop_);
    runtime_->listener_fd = config_.listener_fd;
    runtime_->worker_index = config_.worker_index;
    runtime_->snapshot = config_.snapshot;
    runtime_->max_body_bytes = config_.max_body_bytes;
    runtime_->connections.resize(config_.max_connections > 0 ? config_.max_connections : 16384);
    runtime_->free_list.reserve(runtime_->connections.size());
    for (uint32_t i = 0; i < runtime_->connections.size(); ++i) {
        runtime_->free_list.push_back(static_cast<uint32_t>(runtime_->connections.size() - 1 - i));
    }
    if (runtime_->listener_fd >= 0) {
        if (!runtime_->loop->Add(runtime_->listener_fd, platform::kEventRead | platform::kEventEdge,
                                 make_listener_token(), error_out)) {
            return false;
        }
    }
    return true;
}

int ProxyEngine::Run(volatile sig_atomic_t *stop_flag,
                     int parent_pid,
                     uint64_t shutdown_grace_timeout_ms,
                     std::string *error_out) {
    if (!runtime_ || !runtime_->loop) {
        if (error_out != nullptr) {
            *error_out = "proxy engine not initialized";
        }
        return 2;
    }

    platform::ReadyEvent events[256];
    uint64_t shutdown_deadline_ms = 0;
    while (true) {
        if (parent_pid > 1 && getppid() != parent_pid) {
            if (stop_flag != nullptr) {
                *stop_flag = 1;
            }
        }
        if (stop_flag != nullptr && *stop_flag && runtime_->listener_fd >= 0) {
            runtime_->loop->Remove(runtime_->listener_fd);
            close_fd(runtime_->listener_fd);
            if (shutdown_deadline_ms == 0) {
                shutdown_deadline_ms = now_ms() + shutdown_grace_timeout_ms;
            }
        }
        if (stop_flag != nullptr && *stop_flag) {
            if (runtime_->active_connections == 0) {
                break;
            }
            if (shutdown_deadline_ms != 0 && now_ms() >= shutdown_deadline_ms) {
                break;
            }
        }

        std::string loop_error;
        const int n = runtime_->loop->Wait(events, 256, (stop_flag != nullptr && *stop_flag) ? 100 : 1000, &loop_error);
        const uint64_t now = now_ms();
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (error_out != nullptr) {
                *error_out = loop_error;
            }
            break;
        }
        for (int i = 0; i < n; ++i) {
            const uint64_t token = events[i].token;
            const CoreTag::Kind kind = token_kind(token);
            if (kind == CoreTag::Listener) {
                if (runtime_->listener_fd < 0) {
                    continue;
                }
                for (;;) {
                    int fd = accept_client_socket(runtime_->listener_fd);
                    if (fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        break;
                    }
                    set_tcp_nodelay(fd);
                    if (runtime_->free_list.empty()) {
                        ++runtime_->rejected_connections;
                        close_fd(fd);
                        continue;
                    }
                    const uint32_t idx = runtime_->free_list.back();
                    runtime_->free_list.pop_back();
                    Connection &conn = runtime_->connections[idx];
                    conn.Reset(fd);
                    conn.last_progress_ms = now;
                    ++runtime_->active_connections;
                    if (runtime_->active_connections > runtime_->peak_active_connections) {
                        runtime_->peak_active_connections = runtime_->active_connections;
                    }
                    const uint32_t desired = desired_client_events(&conn);
                    if (!runtime_->loop->Add(conn.client_fd, desired,
                                             make_conn_token(CoreTag::Client, conn.generation, idx), error_out)) {
                        release_connection(runtime_.get(), &conn);
                        continue;
                    }
                    conn.client_registered = true;
                    conn.client_events = desired;
                    conn.client_token_generation = conn.generation;
                    if (!handle_client_header_read(runtime_.get(), &conn)) {
                        release_connection(runtime_.get(), &conn);
                        continue;
                    }
                }
                continue;
            }

            const uint32_t idx = token_index(token);
            if (idx >= runtime_->connections.size()) {
                continue;
            }
            Connection *conn = &runtime_->connections[idx];
            if (conn->generation != token_generation(token)) {
                continue;
            }
            if (kind == CoreTag::Client) {
                if (conn->client_fd < 0) {
                    continue;
                }
            } else if (kind == CoreTag::Upstream) {
                if (conn->upstream_fd < 0) {
                    continue;
                }
            } else {
                continue;
            }

            const uint32_t event_mask = events[i].events;
            const bool peer_closed = platform::HasEvent(event_mask, platform::kEventError) ||
                                     platform::HasEvent(event_mask, platform::kEventHangup) ||
                                     platform::HasEvent(event_mask, platform::kEventReadHup);

            if (peer_closed) {
                if (kind == CoreTag::Client) {
                    conn->saw_client_eof = true;
                    if (platform::HasEvent(event_mask, platform::kEventError) ||
                        platform::HasEvent(event_mask, platform::kEventHangup)) {
                        if (conn->state != ConnState::ReadClientHeaders && conn->state != ConnState::WriteUpstream) {
                            release_connection(runtime_.get(), conn);
                            continue;
                        }
                        if (!platform::HasEvent(event_mask, platform::kEventRead) && conn->client_buffer.empty()) {
                            release_connection(runtime_.get(), conn);
                            continue;
                        }
                    }
                }
                if (kind == CoreTag::Upstream) {
                    conn->saw_upstream_eof = true;
                    if (conn->state != ConnState::ReadUpstream &&
                        conn->state != ConnState::WriteClient &&
                        conn->state != ConnState::SpliceResponseBody) {
                        release_connection(runtime_.get(), conn);
                        continue;
                    }
                }
            }

            bool ok = true;
            if (kind == CoreTag::Client) {
                const bool client_progress = platform::HasEvent(event_mask, platform::kEventRead) ||
                    (conn->saw_client_eof &&
                     (conn->state == ConnState::ReadClientHeaders || conn->state == ConnState::WriteUpstream));
                if (conn->state == ConnState::ReadClientHeaders && client_progress) {
                    ok = handle_client_header_read(runtime_.get(), conn);
                } else if (conn->state == ConnState::WriteUpstream && client_progress) {
                    ok = handle_upstream_write(runtime_.get(), conn);
                } else if (conn->state == ConnState::WriteClient && platform::HasEvent(event_mask, platform::kEventWrite)) {
                    ok = handle_client_write(runtime_.get(), conn);
                } else if (conn->state == ConnState::SpliceResponseBody && platform::HasEvent(event_mask, platform::kEventWrite)) {
                    ok = handle_splice_response_body(runtime_.get(), conn);
                }
            } else if (kind == CoreTag::Upstream) {
                const bool upstream_connect_ready = platform::HasEvent(event_mask, platform::kEventWrite) || peer_closed;
                const bool upstream_read_ready = platform::HasEvent(event_mask, platform::kEventRead) ||
                    (conn->saw_upstream_eof && conn->state == ConnState::ReadUpstream);
                const bool upstream_splice_ready = platform::HasEvent(event_mask, platform::kEventRead) ||
                    (conn->saw_upstream_eof && conn->state == ConnState::SpliceResponseBody);
                if (conn->state == ConnState::ConnectUpstream && upstream_connect_ready) {
                    ok = handle_upstream_connect(runtime_.get(), conn);
                } else if (conn->state == ConnState::WriteUpstream && platform::HasEvent(event_mask, platform::kEventWrite)) {
                    ok = handle_upstream_write(runtime_.get(), conn);
                } else if (conn->state == ConnState::ReadUpstream && upstream_read_ready) {
                    ok = handle_upstream_read(runtime_.get(), conn);
                } else if (conn->state == ConnState::SpliceResponseBody && upstream_splice_ready) {
                    ok = handle_splice_response_body(runtime_.get(), conn);
                }
            }
            if (!ok) {
                release_connection(runtime_.get(), conn);
            }
        }
        reap_idle(runtime_.get(), now);
    }

    if (emit_worker_stats()) {
        std::fprintf(stderr,
                     "gateway-worker[%d] req=%llu active=%llu peak=%llu splice_hits=%llu splice_fallbacks=%llu header_passthrough=%llu\n",
                     runtime_->worker_index,
                     static_cast<unsigned long long>(runtime_->total_requests),
                     static_cast<unsigned long long>(runtime_->active_connections),
                     static_cast<unsigned long long>(runtime_->peak_active_connections),
                     static_cast<unsigned long long>(runtime_->splice_hits),
                     static_cast<unsigned long long>(runtime_->splice_fallbacks),
                     static_cast<unsigned long long>(runtime_->header_passthrough_hits));
        std::fprintf(stderr,
                     "gateway-worker[%d] errors=%llu timeouts=%llu rejected=%llu fallbacks=%llu\n",
                     runtime_->worker_index,
                     static_cast<unsigned long long>(runtime_->total_errors),
                     static_cast<unsigned long long>(runtime_->total_timeouts),
                     static_cast<unsigned long long>(runtime_->rejected_connections),
                     static_cast<unsigned long long>(runtime_->fallback_hits));
    }
    return 0;
}

} // namespace core
} // namespace gateway
} // namespace kislay
