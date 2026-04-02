#include "epoll_server.h"

#include "connection.h"
#include "http_parser.h"

#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/wait.h>
#endif

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

namespace kislay {
namespace gateway {
namespace epoll {

#ifndef __linux__
EpollServer::EpollServer(EpollServerConfig config) : config_(config), running_(false) {}
EpollServer::~EpollServer() {}
bool EpollServer::Start(std::string *error_out) {
    if (error_out != nullptr) {
        *error_out = "epoll gateway engine is Linux-only";
    }
    return false;
}
void EpollServer::Stop() {}
bool EpollServer::running() const { return running_; }
#else
namespace {

volatile sig_atomic_t g_worker_stop = 0;

static void handle_term_signal(int) {
    g_worker_stop = 1;
}

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

static void raise_nofile_limit() {
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
        return;
    }
    if (limit.rlim_cur == limit.rlim_max) {
        return;
    }
    limit.rlim_cur = limit.rlim_max;
    setrlimit(RLIMIT_NOFILE, &limit);
}

static void close_fd(int &fd) {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

static bool set_nonblocking(int fd, std::string *error_out) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        if (error_out) {
            *error_out = std::strerror(errno);
        }
        return false;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        if (error_out) {
            *error_out = std::strerror(errno);
        }
        return false;
    }
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

static bool prepare_snapshot(RouteSnapshot *snapshot, std::string *error_out) {
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

static int create_listen_socket(const char *host, uint16_t port, std::string *error_out) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;

    char port_buf[16];
    std::snprintf(port_buf, sizeof(port_buf), "%u", static_cast<unsigned>(port));

    struct addrinfo *result = nullptr;
    const int rc = getaddrinfo(host, port_buf, &hints, &result);
    if (rc != 0 || result == nullptr) {
        if (error_out) {
            *error_out = gai_strerror(rc);
        }
        if (result != nullptr) {
            freeaddrinfo(result);
        }
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *it = result; it != nullptr; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
        if (!set_nonblocking(fd, error_out)) {
            close_fd(fd);
            continue;
        }
        if (bind(fd, it->ai_addr, it->ai_addrlen) == 0 && listen(fd, 1024) == 0) {
            break;
        }
        close_fd(fd);
    }
    freeaddrinfo(result);

    if (fd < 0 && error_out != nullptr && error_out->empty()) {
        *error_out = std::strerror(errno);
    }
    return fd;
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

static void queue_error_response(Connection *conn, int status, const char *message, bool close_after) {
    conn->client_buffer.clear();
    conn->safe_upstream_keep_alive = false;
    char header[512];
    const char *status_text = "Bad Request";
    switch (status) {
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        case 413: status_text = "Payload Too Large"; break;
        case 500: status_text = "Internal Server Error"; break;
        case 501: status_text = "Not Implemented"; break;
        case 502: status_text = "Bad Gateway"; break;
        case 503: status_text = "Service Unavailable"; break;
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

    const std::size_t body_consumed = body_offset + to_copy;
    const std::size_t total_read = conn->client_buffer.end;
    conn->pipelined_bytes = total_read > (body_offset + conn->request_body_expected);
    conn->client_buffer.clear();
    if (body_available > to_copy) {
        const std::size_t remain = body_available - to_copy;
        if (remain > 0) {
            std::memmove(conn->client_buffer.data(), request_buffer + body_offset + to_copy, remain);
            conn->client_buffer.end = remain;
        }
    }
    (void) body_consumed;

    if (conn->upstream_buffer.empty()) {
        if (error_out) {
            *error_out = "failed to build upstream request";
        }
        return false;
    }
    return true;
}

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

    int epoll_fd;
    int listen_fd;
    EpollTag listener_tag;
    std::vector<Connection> connections;
    std::vector<uint32_t> free_list;
    RouteSnapshot snapshot;
    std::size_t max_body_bytes;
    std::unordered_map<PoolKey, std::deque<int>, PoolKeyHash> upstream_pool;

    WorkerRuntime() : epoll_fd(-1), listen_fd(-1), max_body_bytes(0) {
        listener_tag.kind = EpollTag::Listener;
        listener_tag.conn = nullptr;
    }
};

static bool refresh_client_interest(WorkerRuntime *rt, Connection *conn);
static bool refresh_upstream_interest(WorkerRuntime *rt, Connection *conn);
static bool finish_response(WorkerRuntime *rt, Connection *conn);
static bool handle_upstream_write(WorkerRuntime *rt, Connection *conn);
static bool handle_upstream_read(WorkerRuntime *rt, Connection *conn);
static bool handle_client_write(WorkerRuntime *rt, Connection *conn);

static uint32_t connection_index(WorkerRuntime *rt, Connection *conn) {
    return static_cast<uint32_t>(conn - &rt->connections[0]);
}

static uint64_t make_listener_token() {
    return static_cast<uint64_t>(EpollTag::Listener) << 56;
}

static uint64_t make_conn_token(EpollTag::Kind kind, uint32_t generation, uint32_t index) {
    return (static_cast<uint64_t>(kind) << 56) |
           ((static_cast<uint64_t>(generation) & 0x0FFFFFFFu) << 28) |
           (static_cast<uint64_t>(index) & 0x0FFFFFFFu);
}

static EpollTag::Kind token_kind(uint64_t token) {
    return static_cast<EpollTag::Kind>((token >> 56) & 0xFFu);
}

static uint32_t token_generation(uint64_t token) {
    return static_cast<uint32_t>((token >> 28) & 0x0FFFFFFFu);
}

static uint32_t token_index(uint64_t token) {
    return static_cast<uint32_t>(token & 0x0FFFFFFFu);
}

static uint32_t desired_client_events(const Connection *conn) {
    uint32_t events = EPOLLET | EPOLLRDHUP;
    switch (conn->state) {
        case ConnState::ReadClientHeaders:
            events |= EPOLLIN;
            break;
        case ConnState::WriteUpstream:
            if (conn->request_body_forwarded < conn->request_body_expected && conn->client_buffer.writable() > 0) {
                events |= EPOLLIN;
            }
            break;
        case ConnState::WriteClient:
            if (!conn->client_buffer.empty() || !conn->upstream_buffer.empty()) {
                events |= EPOLLOUT;
            }
            break;
        default:
            break;
    }
    return events;
}

static uint32_t desired_upstream_events(const Connection *conn) {
    uint32_t events = EPOLLET | EPOLLRDHUP;
    switch (conn->state) {
        case ConnState::ConnectUpstream:
        case ConnState::WriteUpstream:
            events |= EPOLLOUT;
            break;
        case ConnState::ReadUpstream:
            if (conn->upstream_buffer.writable() > 0) {
                events |= EPOLLIN;
            }
            break;
        default:
            break;
    }
    return events;
}

static bool arm_error_response(WorkerRuntime *rt, Connection *conn) {
    conn->state = ConnState::WriteClient;
    return refresh_client_interest(rt, conn) && refresh_upstream_interest(rt, conn);
}

static bool epoll_add(int epoll_fd, int fd, uint32_t events, uint64_t token) {
    struct epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.u64 = token;
    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == 0;
}

static bool epoll_mod(int epoll_fd, int fd, uint32_t events, uint64_t token) {
    struct epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.u64 = token;
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == 0;
}

static void epoll_del(int epoll_fd, int fd) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
}

static void release_connection(WorkerRuntime *rt, Connection *conn) {
    if (conn->client_fd >= 0) {
        epoll_del(rt->epoll_fd, conn->client_fd);
        close_fd(conn->client_fd);
    }
    if (conn->upstream_fd >= 0) {
        epoll_del(rt->epoll_fd, conn->upstream_fd);
        close_fd(conn->upstream_fd);
    }
    const uint32_t idx = static_cast<uint32_t>(conn - &rt->connections[0]);
    conn->Reset(-1);
    rt->free_list.push_back(idx);
}

static bool refresh_client_interest(WorkerRuntime *rt, Connection *conn) {
    if (conn->client_fd < 0) {
        return true;
    }
    const uint32_t events = desired_client_events(conn);
    if (events == conn->client_events) {
        return true;
    }
    if (!epoll_mod(rt->epoll_fd, conn->client_fd, events,
                   make_conn_token(EpollTag::Client, conn->generation, connection_index(rt, conn)))) {
        return false;
    }
    conn->client_events = events;
    return true;
}

static bool refresh_upstream_interest(WorkerRuntime *rt, Connection *conn) {
    if (conn->upstream_fd < 0) {
        return true;
    }
    const uint32_t events = desired_upstream_events(conn);
    if (events == conn->upstream_events) {
        return true;
    }
    if (!epoll_mod(rt->epoll_fd, conn->upstream_fd, events,
                   make_conn_token(EpollTag::Upstream, conn->generation, connection_index(rt, conn)))) {
        return false;
    }
    conn->upstream_events = events;
    return true;
}

static void close_upstream_side(WorkerRuntime *rt, Connection *conn) {
    if (conn->upstream_fd >= 0) {
        epoll_del(rt->epoll_fd, conn->upstream_fd);
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
    pfd.events = POLLIN | POLLERR | POLLHUP | POLLRDHUP;
    const int poll_rc = poll(&pfd, 1, 0);
    if (poll_rc < 0) {
        return false;
    }
    if (poll_rc > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL | POLLIN)) != 0) {
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

    std::unordered_map<WorkerRuntime::PoolKey, std::deque<int>, WorkerRuntime::PoolKeyHash>::iterator it =
        rt->upstream_pool.find(pool_key_for(target));
    if (it == rt->upstream_pool.end()) {
        return -1;
    }

    std::deque<int> &bucket = it->second;
    while (!bucket.empty()) {
        const int fd = bucket.back();
        bucket.pop_back();
        if (pooled_socket_healthy(fd)) {
            return fd;
        }
        int doomed = fd;
        close_fd(doomed);
    }
    rt->upstream_pool.erase(it);
    return -1;
}

static void recycle_upstream_side(WorkerRuntime *rt, Connection *conn) {
    if (conn->upstream_fd < 0) {
        return;
    }

    const bool body_complete =
        conn->response.no_body ||
        (conn->response.has_content_length && conn->response_body_forwarded >= conn->response_body_expected);
    const bool safe_to_reuse =
        conn->safe_upstream_keep_alive &&
        conn->upstream_connected &&
        !conn->saw_upstream_eof &&
        body_complete &&
        conn->client_buffer.empty() &&
        conn->upstream_buffer.empty() &&
        conn->upstream_target != nullptr;

    const int fd = conn->upstream_fd;
    epoll_del(rt->epoll_fd, fd);
    conn->upstream_fd = -1;
    conn->upstream_events = 0;

    if (!safe_to_reuse || !pooled_socket_healthy(fd)) {
        int doomed = fd;
        close_fd(doomed);
        return;
    }

    std::deque<int> &bucket = rt->upstream_pool[pool_key_for(conn->upstream_target)];
    if (bucket.size() >= 16) {
        int doomed = fd;
        close_fd(doomed);
        return;
    }
    bucket.push_back(fd);
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

static bool open_upstream(WorkerRuntime *rt, Connection *conn) {
    int fd = acquire_upstream_from_pool(rt, conn->upstream_target);
    if (fd >= 0) {
        conn->upstream_fd = fd;
        conn->upstream_connected = true;
        conn->state = ConnState::WriteUpstream;
        const uint32_t events = desired_upstream_events(conn);
        if (!epoll_add(rt->epoll_fd, conn->upstream_fd, events,
                       make_conn_token(EpollTag::Upstream, conn->generation, connection_index(rt, conn)))) {
            close_fd(conn->upstream_fd);
            queue_error_response(conn, 502, "Upstream reuse failed", true);
            return false;
        }
        conn->upstream_events = events;
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
    const uint32_t events = desired_upstream_events(conn);
    if (!epoll_add(rt->epoll_fd, conn->upstream_fd, events,
                   make_conn_token(EpollTag::Upstream, conn->generation, connection_index(rt, conn)))) {
        close_fd(conn->upstream_fd);
        queue_error_response(conn, 502, "Upstream connect failed", true);
        return false;
    }
    conn->upstream_events = events;
    if (rc == 0) {
        conn->upstream_connected = true;
        conn->state = ConnState::WriteUpstream;
        return handle_upstream_write(rt, conn);
    }
    return true;
}

static bool flush_iov(int fd, FixedBuffer<32768> *first, FixedBuffer<32768> *second, bool *blocked) {
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
    for (;;) {
        const ssize_t written = writev(fd, iov, iovcnt);
        if (written > 0) {
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
                return true;
            }
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (blocked != nullptr) {
                *blocked = true;
            }
            return true;
        }
        return false;
    }
}

static bool read_into_buffer(int fd, FixedBuffer<32768> *buffer, bool *saw_eof) {
    for (;;) {
        buffer->compact_if_needed();
        if (buffer->writable() == 0) {
            return true;
        }
        const ssize_t n = recv(fd, buffer->write_ptr(), buffer->writable(), 0);
        if (n > 0) {
            buffer->produced(static_cast<std::size_t>(n));
            continue;
        }
        if (n == 0) {
            if (saw_eof != nullptr) {
                *saw_eof = true;
            }
            return true;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return true;
        }
        return false;
    }
}

static bool handle_client_header_read(WorkerRuntime *rt, Connection *conn) {
    if (!read_into_buffer(conn->client_fd, &conn->client_buffer, &conn->saw_client_eof)) {
        return false;
    }
    if (conn->saw_client_eof && conn->client_buffer.empty()) {
        return false;
    }

    const char *error = nullptr;
    const ParseStatus status = ParseRequestHead(conn->client_buffer.data(), conn->client_buffer.end,
                                                &conn->request, conn->request_headers, 64, &error);
    if (status == ParseStatus::NeedMore) {
        return true;
    }
    if (status == ParseStatus::Error) {
        queue_error_response(conn, 400, error != nullptr ? error : "invalid request", true);
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
    if (!refresh_upstream_interest(rt, conn) || !refresh_client_interest(rt, conn)) {
        return false;
    }
    return handle_upstream_write(rt, conn);
}

static bool handle_upstream_write(WorkerRuntime *rt, Connection *conn) {
    bool blocked = false;
    if (!flush_iov(conn->upstream_fd, &conn->upstream_buffer, &conn->client_buffer, &blocked)) {
        queue_error_response(conn, 502, "upstream write failed", true);
        return arm_error_response(rt, conn);
    }

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

    conn->request_body_forwarded = conn->request_body_expected - conn->client_buffer.readable();
    if (conn->upstream_buffer.empty() && conn->client_buffer.empty() && conn->request_body_forwarded >= conn->request_body_expected) {
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
    if (conn->response.has_content_length) {
        // already forwarded in original headers if present; do nothing
    } else if (conn->response.no_body) {
        append_literal(conn->client_buffer, "Content-Length: 0\r\n");
    }
    append_literal(conn->client_buffer, conn->safe_client_keep_alive ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n");
    return true;
}

static bool handle_upstream_read(WorkerRuntime *rt, Connection *conn) {
    if (!read_into_buffer(conn->upstream_fd, &conn->upstream_buffer, &conn->saw_upstream_eof)) {
        queue_error_response(conn, 502, "upstream read failed", true);
        return arm_error_response(rt, conn);
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
        conn->safe_client_keep_alive = conn->client_keep_alive && !conn->pipelined_bytes && (conn->response.has_content_length || conn->response.no_body) && !conn->response.chunked && !conn->response.close_delimited;
        conn->close_after_response = !conn->safe_client_keep_alive;
        build_client_response_header(conn);
        conn->upstream_buffer.start = conn->response.headers_end;
        if (conn->upstream_buffer.start > conn->upstream_buffer.end) {
            conn->upstream_buffer.start = conn->upstream_buffer.end;
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

static bool finish_response(WorkerRuntime *rt, Connection *conn) {
    recycle_upstream_side(rt, conn);
    if (conn->safe_client_keep_alive) {
        conn->ResetForNextRequest();
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
    if (!flush_iov(conn->client_fd, &conn->client_buffer, &conn->upstream_buffer, &blocked)) {
        return false;
    }
    const std::size_t body_after = conn->upstream_buffer.readable();
    if (body_before >= body_after) {
        conn->response_body_forwarded += static_cast<uint64_t>(body_before - body_after);
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

static void reap_idle(WorkerRuntime *rt, uint64_t now) {
    for (std::size_t i = 0; i < rt->connections.size(); ++i) {
        Connection &conn = rt->connections[i];
        if (conn.client_fd < 0) {
            continue;
        }
        if (now > conn.last_activity_ms && (now - conn.last_activity_ms) > 30000ull) {
            release_connection(rt, &conn);
        }
    }
}

static void worker_loop(EpollServerConfig config) {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_term_signal;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);

    WorkerRuntime rt;
    rt.snapshot = config.snapshot;
    rt.max_body_bytes = config.max_body_bytes;
    rt.listen_fd = create_listen_socket(config.listen_host.c_str(), config.listen_port, nullptr);
    if (rt.listen_fd < 0) {
        _exit(2);
    }
    rt.epoll_fd = epoll_create1(0);
    if (rt.epoll_fd < 0) {
        close_fd(rt.listen_fd);
        _exit(2);
    }
    rt.connections.resize(16384);
    rt.free_list.reserve(rt.connections.size());
    for (uint32_t i = 0; i < rt.connections.size(); ++i) {
        rt.free_list.push_back(static_cast<uint32_t>(rt.connections.size() - 1 - i));
    }
    if (!epoll_add(rt.epoll_fd, rt.listen_fd, EPOLLIN | EPOLLET, make_listener_token())) {
        close_fd(rt.listen_fd);
        close_fd(rt.epoll_fd);
        _exit(2);
    }

    struct epoll_event events[256];
    while (!g_worker_stop) {
        const int n = epoll_wait(rt.epoll_fd, events, 256, 1000);
        const uint64_t now = now_ms();
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        for (int i = 0; i < n; ++i) {
            const uint64_t token = events[i].data.u64;
            const EpollTag::Kind kind = token_kind(token);
            if (kind == EpollTag::Listener) {
                for (;;) {
                    sockaddr_storage addr;
                    socklen_t addr_len = sizeof(addr);
                    int fd = accept4(rt.listen_fd, reinterpret_cast<sockaddr *>(&addr), &addr_len, SOCK_NONBLOCK);
                    if (fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        break;
                    }
                    set_tcp_nodelay(fd);
                    if (rt.free_list.empty()) {
                        close_fd(fd);
                        continue;
                    }
                    const uint32_t idx = rt.free_list.back();
                    rt.free_list.pop_back();
                    Connection &conn = rt.connections[idx];
                    conn.Reset(fd);
                    conn.last_activity_ms = now;
                    const uint32_t events = desired_client_events(&conn);
                    if (!epoll_add(rt.epoll_fd, conn.client_fd, events,
                                   make_conn_token(EpollTag::Client, conn.generation, idx))) {
                        release_connection(&rt, &conn);
                        continue;
                    }
                    conn.client_events = events;
                    if (!handle_client_header_read(&rt, &conn)) {
                        release_connection(&rt, &conn);
                        continue;
                    }
                }
                continue;
            }

            const uint32_t idx = token_index(token);
            if (idx >= rt.connections.size()) {
                continue;
            }
            Connection *conn = &rt.connections[idx];
            if (conn->generation != token_generation(token)) {
                continue;
            }
            if (kind == EpollTag::Client) {
                if (conn->client_fd < 0) {
                    continue;
                }
            } else if (kind == EpollTag::Upstream) {
                if (conn->upstream_fd < 0) {
                    continue;
                }
            } else {
                continue;
            }
            conn->last_activity_ms = now;
            const uint32_t event_mask = events[i].events;
            const bool peer_closed = (event_mask & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0;

            if (peer_closed) {
                if (kind == EpollTag::Client) {
                    if ((event_mask & (EPOLLERR | EPOLLHUP)) == 0) {
                        // Client half-close is handled lazily on the next recv()/idle reap so it does not break keep-alive reuse.
                    } else {
                        conn->saw_client_eof = true;
                        if (conn->state != ConnState::ReadClientHeaders && conn->state != ConnState::WriteUpstream) {
                            release_connection(&rt, conn);
                            continue;
                        }
                        if ((events[i].events & EPOLLIN) == 0 && conn->client_buffer.empty()) {
                            release_connection(&rt, conn);
                            continue;
                        }
                    }
                }
                if (kind == EpollTag::Upstream) {
                    conn->saw_upstream_eof = true;
                    if (conn->state != ConnState::ReadUpstream && conn->state != ConnState::WriteClient) {
                        release_connection(&rt, conn);
                        continue;
                    }
                }
            }

            bool ok = true;
            if (kind == EpollTag::Client) {
                const bool client_progress = (event_mask & EPOLLIN) || (conn->saw_client_eof &&
                    (conn->state == ConnState::ReadClientHeaders || conn->state == ConnState::WriteUpstream));
                if (conn->state == ConnState::ReadClientHeaders && client_progress) {
                    ok = handle_client_header_read(&rt, conn);
                } else if (conn->state == ConnState::WriteUpstream && client_progress) {
                    ok = handle_upstream_write(&rt, conn);
                } else if (conn->state == ConnState::WriteClient && (event_mask & EPOLLOUT)) {
                    ok = handle_client_write(&rt, conn);
                }
            } else if (kind == EpollTag::Upstream) {
                const bool upstream_connect_ready = (event_mask & EPOLLOUT) || peer_closed;
                const bool upstream_read_ready = (event_mask & EPOLLIN) || (conn->saw_upstream_eof &&
                    conn->state == ConnState::ReadUpstream);
                if (conn->state == ConnState::ConnectUpstream && upstream_connect_ready) {
                    ok = handle_upstream_connect(&rt, conn);
                } else if (conn->state == ConnState::WriteUpstream && (event_mask & EPOLLOUT)) {
                    ok = handle_upstream_write(&rt, conn);
                } else if (conn->state == ConnState::ReadUpstream && upstream_read_ready) {
                    ok = handle_upstream_read(&rt, conn);
                }
            }
            if (!ok) {
                release_connection(&rt, conn);
            }
        }
        reap_idle(&rt, now);
    }

    for (std::size_t i = 0; i < rt.connections.size(); ++i) {
        if (rt.connections[i].client_fd >= 0) {
            release_connection(&rt, &rt.connections[i]);
        }
    }
    for (std::unordered_map<WorkerRuntime::PoolKey, std::deque<int>, WorkerRuntime::PoolKeyHash>::iterator it =
             rt.upstream_pool.begin();
         it != rt.upstream_pool.end();
         ++it) {
        std::deque<int> &bucket = it->second;
        while (!bucket.empty()) {
            int fd = bucket.back();
            bucket.pop_back();
            close_fd(fd);
        }
    }
    close_fd(rt.listen_fd);
    close_fd(rt.epoll_fd);
    _exit(0);
}

} // namespace

EpollServer::EpollServer(EpollServerConfig config)
    : config_(config), running_(false) {}

EpollServer::~EpollServer() {
    Stop();
}

bool EpollServer::Start(std::string *error_out) {
    if (running_) {
        return true;
    }
    if (config_.worker_processes < 1) {
        config_.worker_processes = 1;
    }
    if (!prepare_snapshot(&config_.snapshot, error_out)) {
        return false;
    }
    config_.snapshot.Finalize();
    raise_nofile_limit();
    workers_.clear();
    for (int i = 0; i < config_.worker_processes; ++i) {
        const pid_t pid = fork();
        if (pid < 0) {
            if (error_out != nullptr) {
                *error_out = std::strerror(errno);
            }
            Stop();
            return false;
        }
        if (pid == 0) {
            worker_loop(config_);
        }
        workers_.push_back(static_cast<int>(pid));
    }
    running_ = true;
    return true;
}

void EpollServer::Stop() {
    if (!running_) {
        return;
    }
    for (std::size_t i = 0; i < workers_.size(); ++i) {
        if (workers_[i] > 0) {
            kill(workers_[i], SIGTERM);
        }
    }
    for (std::size_t i = 0; i < workers_.size(); ++i) {
        if (workers_[i] > 0) {
            int status = 0;
            waitpid(workers_[i], &status, 0);
        }
    }
    workers_.clear();
    running_ = false;
}

bool EpollServer::running() const {
    return running_;
}
#endif

} // namespace epoll
} // namespace gateway
} // namespace kislay
