#pragma once

#include "../core/proxy_engine.h"

#include <memory>
#include <string>
#include <vector>

namespace kislay {
namespace gateway {
namespace epoll {

using ControlRoute = core::ControlRoute;
using ServiceRegistryEntry = core::ServiceRegistryEntry;
using RouteSnapshotEntry = core::RouteSnapshotEntry;
using RouteSnapshot = core::RouteSnapshot;
using UpstreamTarget = core::UpstreamTarget;

struct TlsConfig {
    bool enabled;
    std::string cert_path;
    std::string key_path;
    std::string min_version;

    TlsConfig()
        : enabled(false), min_version("tls1.2") {}
};

struct EpollServerConfig {
    std::string listen_host;
    uint16_t listen_port;
    int worker_processes;
    int worker_index;
    std::size_t max_body_bytes;
    std::size_t max_connections;
    std::string runtime_engine;
    TlsConfig tls;
    core::DiscoveryConfig discovery;
    RouteSnapshot snapshot;

    EpollServerConfig()
        : listen_port(0),
          worker_processes(0),
          worker_index(0),
          max_body_bytes(0),
          max_connections(16384),
          runtime_engine("auto") {}
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
