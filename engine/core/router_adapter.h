#pragma once

#include "upstream.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
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
};

struct ServiceDefinition {
    uint32_t id;
    std::string service;
    std::vector<UpstreamTarget> targets;

    ServiceDefinition() : id(UINT32_MAX) {}
};

struct ServiceTargetSet {
    std::vector<UpstreamTarget> targets;
    mutable uint32_t next_index;

    ServiceTargetSet() : next_index(0) {}
};

class ServiceSnapshot {
public:
    ServiceSnapshot() = default;

    void Add(const ServiceDefinition &definition) {
        if (definition.id >= services_.size()) {
            services_.resize(static_cast<std::size_t>(definition.id) + 1);
        }
        services_[definition.id].targets = definition.targets;
        services_[definition.id].next_index = 0;
    }

    bool Resolve(uint32_t service_id, const UpstreamTarget **target) const {
        if (target == nullptr || service_id >= services_.size()) {
            return false;
        }
        const ServiceTargetSet &set = services_[service_id];
        if (set.targets.empty()) {
            return false;
        }
        if (set.targets.size() == 1) {
            *target = &set.targets[0];
            return true;
        }
        const uint32_t slot = set.next_index++ % static_cast<uint32_t>(set.targets.size());
        *target = &set.targets[slot];
        return true;
    }

    std::size_t size() const {
        return services_.size();
    }

    const ServiceTargetSet *Find(uint32_t service_id) const {
        if (service_id >= services_.size()) {
            return nullptr;
        }
        return &services_[service_id];
    }

private:
    std::vector<ServiceTargetSet> services_;
};

struct RouteSnapshotEntry {
    std::string method;
    std::string path;
    bool wildcard;
    bool use_service;
    uint32_t service_id;
    std::string service;
    UpstreamTarget target;

    RouteSnapshotEntry()
        : wildcard(false), use_service(false), service_id(UINT32_MAX) {}
};

class RouteSnapshot {
public:
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
        uint32_t id = UINT32_MAX;
        std::unordered_map<std::string, uint32_t>::const_iterator existing = service_ids_.find(service.service);
        if (existing != service_ids_.end()) {
            id = existing->second;
            service_definitions_[id].targets = service.targets;
            return;
        }
        id = static_cast<uint32_t>(service_definitions_.size());
        service_ids_[service.service] = id;
        ServiceDefinition definition;
        definition.id = id;
        definition.service = service.service;
        definition.targets = service.targets;
        service_definitions_.push_back(definition);
    }

    void Finalize() {
        exact_.clear();
        prefix_.clear();
        for (std::size_t i = 0; i < routes_.size(); ++i) {
            RouteSnapshotEntry &entry = routes_[i];
            bind_service(entry);
            if (!entry.wildcard && entry.method != "*") {
                exact_[HashPair(entry.method.data(), entry.method.size(), entry.path.data(), entry.path.size())] = &entry;
            } else {
                prefix_.push_back(&entry);
            }
        }
        bind_service(fallback_);
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

    bool Resolve(const RouteSnapshotEntry *entry,
                 const ServiceSnapshot *services,
                 const UpstreamTarget **target) const {
        if (entry == nullptr || target == nullptr) {
            return false;
        }
        if (!entry->use_service) {
            *target = &entry->target;
            return true;
        }
        if (services == nullptr || entry->service_id == UINT32_MAX) {
            return false;
        }
        return services->Resolve(entry->service_id, target);
    }

    std::shared_ptr<ServiceSnapshot> BuildInitialServiceSnapshot() const {
        std::shared_ptr<ServiceSnapshot> snapshot = std::make_shared<ServiceSnapshot>();
        for (std::size_t i = 0; i < service_definitions_.size(); ++i) {
            snapshot->Add(service_definitions_[i]);
        }
        return snapshot;
    }

    const std::vector<ServiceDefinition> &service_definitions() const { return service_definitions_; }
    std::vector<ServiceDefinition> &mutable_service_definitions() { return service_definitions_; }
    std::vector<RouteSnapshotEntry> &mutable_routes() { return routes_; }
    bool has_fallback() const { return has_fallback_; }
    RouteSnapshotEntry *mutable_fallback() { return has_fallback_ ? &fallback_ : nullptr; }

private:
    void bind_service(RouteSnapshotEntry &entry) {
        if (!entry.use_service || entry.service.empty()) {
            entry.service_id = UINT32_MAX;
            return;
        }
        std::unordered_map<std::string, uint32_t>::const_iterator it = service_ids_.find(entry.service);
        entry.service_id = (it == service_ids_.end()) ? UINT32_MAX : it->second;
    }

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
    std::vector<ServiceDefinition> service_definitions_;
    std::unordered_map<std::string, uint32_t> service_ids_;
    RouteSnapshotEntry fallback_;
    bool has_fallback_;
};

} // namespace core
} // namespace gateway
} // namespace kislay
