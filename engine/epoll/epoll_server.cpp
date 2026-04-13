#include "epoll_server.h"

#include "epoll_loop.h"
#include "../core/proxy_engine.h"
#include "../kqueue/kqueue_loop.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <memory>
#include <string>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#endif

#ifdef __linux__
#include <sched.h>
#include <sys/prctl.h>
#endif

namespace kislay {
namespace gateway {
namespace epoll {

namespace {

volatile sig_atomic_t g_worker_stop = 0;
static const uint64_t kShutdownGraceTimeoutMs = 5000ull;

static void handle_term_signal(int) {
    g_worker_stop = 1;
}

static uint64_t now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000ull + static_cast<uint64_t>(ts.tv_nsec / 1000000ull);
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

static int online_cpu_count() {
    const long count = sysconf(_SC_NPROCESSORS_ONLN);
    return count > 0 ? static_cast<int>(count) : 1;
}

static int default_worker_processes() {
    const int cpus = online_cpu_count();
    if (cpus <= 2) {
        return cpus > 0 ? cpus : 1;
    }
    int workers = cpus / 2;
    if (workers < 2) {
        workers = 2;
    }
    if (workers > 4) {
        workers = 4;
    }
    return workers > 0 ? workers : 1;
}

static void bind_worker_to_cpu(int worker_index) {
#ifdef __linux__
    const int cpu_count = online_cpu_count();
    if (cpu_count <= 0) {
        return;
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(worker_index % cpu_count, &set);
    sched_setaffinity(0, sizeof(set), &set);
#else
    (void) worker_index;
#endif
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

static void close_fd(int &fd) {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
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
        if (error_out != nullptr) {
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
        if (bind(fd, it->ai_addr, it->ai_addrlen) == 0 && listen(fd, SOMAXCONN) == 0) {
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

static std::unique_ptr<platform::EventLoop> create_event_loop(const std::string &engine, std::string *error_out) {
    const std::string requested = engine.empty() ? "auto" : engine;
    if (requested == "auto" || requested == "native") {
#ifdef __linux__
        return std::unique_ptr<platform::EventLoop>(new platform::EpollLoop());
#elif defined(__APPLE__)
        return std::unique_ptr<platform::EventLoop>(new platform::KqueueLoop());
#else
        if (error_out != nullptr) {
            *error_out = "no native gateway event loop is available on this platform";
        }
        return std::unique_ptr<platform::EventLoop>();
#endif
    }
    if (requested == "epoll") {
#ifdef __linux__
        return std::unique_ptr<platform::EventLoop>(new platform::EpollLoop());
#else
        if (error_out != nullptr) {
            *error_out = "epoll gateway engine is Linux-only";
        }
        return std::unique_ptr<platform::EventLoop>();
#endif
    }
    if (requested == "kqueue") {
#ifdef __APPLE__
        return std::unique_ptr<platform::EventLoop>(new platform::KqueueLoop());
#else
        if (error_out != nullptr) {
            *error_out = "kqueue gateway engine is macOS-only";
        }
        return std::unique_ptr<platform::EventLoop>();
#endif
    }
    if (error_out != nullptr) {
        *error_out = "unsupported native gateway engine: " + requested;
    }
    return std::unique_ptr<platform::EventLoop>();
}

static int run_worker(EpollServerConfig config) {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_term_signal;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);

    const pid_t parent_pid = getppid();
#ifdef __linux__
    prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
    bind_worker_to_cpu(config.worker_index);

    std::string error;
    int listen_fd = create_listen_socket(config.listen_host.c_str(), config.listen_port, &error);
    if (listen_fd < 0) {
        return 2;
    }

    std::unique_ptr<platform::EventLoop> loop = create_event_loop(config.runtime_engine, &error);
    if (!loop) {
        close_fd(listen_fd);
        return 2;
    }

    core::ProxyEngineConfig proxy_config;
    proxy_config.listener_fd = listen_fd;
    proxy_config.worker_index = config.worker_index;
    proxy_config.max_body_bytes = config.max_body_bytes;
    proxy_config.max_connections = config.max_connections;
    proxy_config.tls = config.tls;
    proxy_config.discovery = config.discovery;
    proxy_config.snapshot = config.snapshot;

    core::ProxyEngine engine(proxy_config, std::move(loop));
    if (!engine.Initialize(&error)) {
        return 2;
    }
    return engine.Run(&g_worker_stop, static_cast<int>(parent_pid), kShutdownGraceTimeoutMs, &error);
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
    {
        std::string probe_error;
        std::unique_ptr<platform::EventLoop> probe = create_event_loop(config_.runtime_engine, &probe_error);
        if (!probe) {
            if (error_out != nullptr) {
                *error_out = probe_error;
            }
            return false;
        }
    }
    if (config_.worker_processes < 1) {
        config_.worker_processes = default_worker_processes();
    }
    if (!core::PrepareRouteSnapshot(&config_.snapshot, error_out)) {
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
            EpollServerConfig worker_config = config_;
            worker_config.worker_index = i;
            const int rc = run_worker(worker_config);
            std::fflush(stderr);
            std::_Exit(rc);
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
    const uint64_t deadline_ms = now_ms() + kShutdownGraceTimeoutMs + 2000ull;
    for (std::size_t i = 0; i < workers_.size(); ++i) {
        if (workers_[i] > 0) {
            kill(workers_[i], SIGTERM);
        }
    }
    for (std::size_t i = 0; i < workers_.size(); ++i) {
        if (workers_[i] > 0) {
            int status = 0;
            for (;;) {
                const pid_t waited = waitpid(workers_[i], &status, WNOHANG);
                if (waited == workers_[i]) {
                    break;
                }
                if (waited < 0 && errno == ECHILD) {
                    break;
                }
                if (now_ms() >= deadline_ms) {
                    kill(workers_[i], SIGKILL);
                    waitpid(workers_[i], &status, 0);
                    break;
                }
                usleep(100000);
            }
        }
    }
    workers_.clear();
    running_ = false;
}

bool EpollServer::running() const {
    return running_;
}

} // namespace epoll
} // namespace gateway
} // namespace kislay
