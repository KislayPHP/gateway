#pragma once

#include "connection.h"
#include "discovery_manager.h"
#include "router_adapter.h"
#include "../interface/event_loop.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <signal.h>
#include <string>

namespace kislay {
namespace gateway {
namespace core {

struct ProxyEngineConfig {
    int listener_fd;
    int worker_index;
    std::size_t max_body_bytes;
    std::size_t max_connections;
    DiscoveryConfig discovery;
    RouteSnapshot snapshot;

    ProxyEngineConfig() : listener_fd(-1), worker_index(0), max_body_bytes(0), max_connections(16384) {}
};

bool PrepareRouteSnapshot(RouteSnapshot *snapshot, std::string *error_out);

struct WorkerRuntime;

class ProxyEngine {
public:
    ProxyEngine(ProxyEngineConfig config, std::unique_ptr<platform::EventLoop> loop);
    ~ProxyEngine();

    bool Initialize(std::string *error_out);
    int Run(volatile sig_atomic_t *stop_flag,
            int parent_pid,
            uint64_t shutdown_grace_timeout_ms,
            std::string *error_out);

private:
    ProxyEngineConfig config_;
    std::unique_ptr<platform::EventLoop> loop_;
    std::unique_ptr<WorkerRuntime> runtime_;
};

} // namespace core
} // namespace gateway
} // namespace kislay
