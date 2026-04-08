#pragma once

#include "upstream.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace kislay {
namespace gateway {
namespace core {

struct ControlRoute {
    std::string method;
    std::string path;
    bool use_service;
    std::string service;
    UpstreamTarget target;
};

struct ServiceRegistryEntry {
    std::string service;
    std::vector<UpstreamTarget> targets;
    mutable uint32_t next_index;

    ServiceRegistryEntry() : next_index(0) {}
};

struct RouteSnapshotEntry {
    std::string method;
    std::string path;
    bool wildcard;
    bool use_service;
    std::string service;
    UpstreamTarget target;
};

class RouteSnapshot {
public:
    typedef std::unordered_map<std::string, ServiceRegistryEntry>::iterator service_iterator;

    RouteSnapshot() : has_fallback_(false) {}

    void AddRoute(const ControlRoute &route) {
        RouteSnapshotEntry entry;
        entry.method = route.method;
        entry.path = route.path.empty() ? "/" : route.path;
        entry.wildcard = !entry.path.empty() && entry.path[entry.path.size() - 1] == '*';
        entry.use_service = route.use_service;
        entry.service = route.service;
        entry.target = route.target;
        routes_.push_back(entry);
    }

    void SetFallback(const ControlRoute &route) {
        fallback_.method = route.method;
        fallback_.path = route.path.empty() ? "*" : route.path;
        fallback_.wildcard = !fallback_.path.empty() && fallback_.path[fallback_.path.size() - 1] == '*';
        fallback_.use_service = route.use_service;
        fallback_.service = route.service;
        fallback_.target = route.target;
        has_fallback_ = true;
    }

    void AddService(const ServiceRegistryEntry &service) {
        services_[service.service] = service;
    }

    void Finalize() {
        exact_.clear();
        prefix_.clear();
        for (std::size_t i = 0; i < routes_.size(); ++i) {
            RouteSnapshotEntry &entry = routes_[i];
            if (!entry.wildcard && entry.method != "*") {
                exact_[HashPair(entry.method.data(), entry.method.size(), entry.path.data(), entry.path.size())] = &entry;
            } else {
                prefix_.push_back(&entry);
            }
        }
        std::sort(prefix_.begin(), prefix_.end(), [](const RouteSnapshotEntry *a, const RouteSnapshotEntry *b) {
            return a->path.size() > b->path.size();
        });
    }

    const RouteSnapshotEntry *Match(const char *method, std::size_t method_len,
                                    const char *path, std::size_t path_len) const {
        const uint64_t key = HashPair(method, method_len, path, path_len);
        std::unordered_map<uint64_t, const RouteSnapshotEntry *>::const_iterator exact = exact_.find(key);
        if (exact != exact_.end()) {
            const RouteSnapshotEntry *entry = exact->second;
            if (entry != nullptr && entry->method.size() == method_len && entry->path.size() == path_len &&
                std::memcmp(entry->method.data(), method, method_len) == 0 &&
                std::memcmp(entry->path.data(), path, path_len) == 0) {
                return entry;
            }
        }

        for (std::size_t i = 0; i < prefix_.size(); ++i) {
            const RouteSnapshotEntry *entry = prefix_[i];
            if (entry == nullptr) {
                continue;
            }
            if (entry->method != "*" && (entry->method.size() != method_len ||
                                         std::memcmp(entry->method.data(), method, method_len) != 0)) {
                continue;
            }
            if (!entry->wildcard) {
                if (entry->path.size() == path_len && std::memcmp(entry->path.data(), path, path_len) == 0) {
                    return entry;
                }
                continue;
            }
            const std::size_t prefix_len = entry->path.size() - 1;
            if (path_len >= prefix_len && std::memcmp(entry->path.data(), path, prefix_len) == 0) {
                return entry;
            }
        }

        return has_fallback_ ? &fallback_ : nullptr;
    }

    bool Resolve(const RouteSnapshotEntry *entry, const UpstreamTarget **target) const {
        if (entry == nullptr || target == nullptr) {
            return false;
        }
        if (!entry->use_service) {
            *target = &entry->target;
            return true;
        }
        std::unordered_map<std::string, ServiceRegistryEntry>::const_iterator it = services_.find(entry->service);
        if (it == services_.end() || it->second.targets.empty()) {
            return false;
        }
        ServiceRegistryEntry &svc = const_cast<ServiceRegistryEntry &>(it->second);
        const std::size_t idx = svc.next_index++ % svc.targets.size();
        *target = &svc.targets[idx];
        return true;
    }

    std::vector<RouteSnapshotEntry> &mutable_routes() { return routes_; }
    service_iterator services_begin() { return services_.begin(); }
    service_iterator services_end() { return services_.end(); }
    bool has_fallback() const { return has_fallback_; }
    RouteSnapshotEntry *mutable_fallback() { return has_fallback_ ? &fallback_ : nullptr; }

private:
    static uint64_t HashPair(const char *method, std::size_t method_len,
                             const char *path, std::size_t path_len) {
        uint64_t h = 1469598103934665603ull;
        for (std::size_t i = 0; i < method_len; ++i) {
            h ^= static_cast<unsigned char>(method[i]);
            h *= 1099511628211ull;
        }
        h ^= static_cast<unsigned char>(':');
        h *= 1099511628211ull;
        for (std::size_t i = 0; i < path_len; ++i) {
            h ^= static_cast<unsigned char>(path[i]);
            h *= 1099511628211ull;
        }
        return h;
    }

    std::vector<RouteSnapshotEntry> routes_;
    std::unordered_map<uint64_t, const RouteSnapshotEntry *> exact_;
    std::vector<const RouteSnapshotEntry *> prefix_;
    std::unordered_map<std::string, ServiceRegistryEntry> services_;
    RouteSnapshotEntry fallback_;
    bool has_fallback_;
};

} // namespace core
} // namespace gateway
} // namespace kislay
