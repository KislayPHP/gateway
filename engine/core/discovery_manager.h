#pragma once

#include "router_adapter.h"

#include <cstdint>
#include <memory>
#include <string>

namespace kislay {
namespace gateway {
namespace core {

struct DiscoveryConfig {
    enum class Backend {
        Static = 0,
        File,
    };

    bool enabled;
    Backend backend;
    std::string path;
    uint64_t poll_ms;

    DiscoveryConfig() : enabled(false), backend(Backend::Static), poll_ms(1000) {}
};

class DiscoveryManager {
public:
    DiscoveryManager();

    bool Initialize(const RouteSnapshot &snapshot,
                    const DiscoveryConfig &config,
                    std::string *error_out);
    void MaybeRefresh(uint64_t now_ms);
    std::shared_ptr<ServiceSnapshot> Current() const;
    int WaitTimeoutMs() const;

private:
    bool refresh_file_snapshot(std::shared_ptr<ServiceSnapshot> *next, std::string *error_out) const;

    RouteSnapshot route_snapshot_;
    DiscoveryConfig config_;
    std::shared_ptr<ServiceSnapshot> current_;
    uint64_t next_refresh_ms_;
};

} // namespace core
} // namespace gateway
} // namespace kislay
