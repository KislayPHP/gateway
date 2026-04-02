#pragma once

#include "router_adapter.h"

#include <memory>
#include <string>
#include <vector>

namespace kislay {
namespace gateway {
namespace epoll {

struct EpollServerConfig {
    std::string listen_host;
    uint16_t listen_port;
    int worker_processes;
    std::size_t max_body_bytes;
    RouteSnapshot snapshot;

    EpollServerConfig() : listen_port(0), worker_processes(1), max_body_bytes(0) {}
};

class EpollServer {
public:
    explicit EpollServer(EpollServerConfig config);
    ~EpollServer();

    bool Start(std::string *error_out);
    void Stop();
    bool running() const;

private:
    EpollServerConfig config_;
    std::vector<int> workers_;
    bool running_;
};

} // namespace epoll
} // namespace gateway
} // namespace kislay
