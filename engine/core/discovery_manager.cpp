#include "discovery_manager.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <netdb.h>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace kislay {
namespace gateway {
namespace core {
namespace {

static std::string trim_copy(const std::string &value) {
    std::size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start])) != 0) {
        ++start;
    }
    std::size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    return value.substr(start, end - start);
}

static uint32_t fnv1a32(const char *data, std::size_t len) {
    uint32_t hash = 2166136261u;
    for (std::size_t i = 0; i < len; ++i) {
        hash ^= static_cast<unsigned char>(data[i]);
        hash *= 16777619u;
    }
    return hash;
}

static void populate_upstream_request_suffix(UpstreamTarget *target) {
    if (target == nullptr) {
        return;
    }
    target->request_header_suffix.clear();
    target->request_header_suffix.reserve(target->host.size() + 48);
    target->request_header_suffix.append(" HTTP/1.1\r\nHost: ");
    target->request_header_suffix.append(target->host);
    target->request_header_suffix.push_back(':');
    char port_buf[16];
    const int port_len = std::snprintf(port_buf, sizeof(port_buf), "%u", static_cast<unsigned>(target->port));
    if (port_len > 0) {
        target->request_header_suffix.append(port_buf, static_cast<std::size_t>(port_len));
    }
    target->request_header_suffix.append("\r\nConnection: keep-alive\r\n");
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

static bool parse_target_url(const std::string &target, UpstreamTarget *out) {
    if (out == nullptr) {
        return false;
    }
    const std::string value = trim_copy(target);
    const std::size_t scheme = value.find("://");
    if (scheme == std::string::npos) {
        return false;
    }

    const std::string protocol = value.substr(0, scheme);
    std::string remainder = value.substr(scheme + 3);
    bool tls = false;
    if (protocol == "http") {
        tls = false;
    } else if (protocol == "https") {
        tls = true;
    } else {
        return false;
    }

    std::string base_path = "/";
    const std::size_t slash = remainder.find('/');
    if (slash != std::string::npos) {
        base_path = remainder.substr(slash);
        remainder = remainder.substr(0, slash);
        if (base_path.empty()) {
            base_path = "/";
        }
    }

    const std::size_t colon = remainder.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= remainder.size()) {
        return false;
    }

    char *end_ptr = nullptr;
    const long port = std::strtol(remainder.c_str() + colon + 1, &end_ptr, 10);
    if (end_ptr == nullptr || *end_ptr != '\0' || port <= 0 || port > 65535) {
        return false;
    }

    out->host = remainder.substr(0, colon);
    out->port = static_cast<uint16_t>(port);
    out->use_tls = tls;
    out->base_path = base_path;
    return true;
}

static std::vector<std::string> split_targets(const std::string &value) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= value.size()) {
        const std::size_t comma = value.find(',', start);
        std::string chunk = comma == std::string::npos ? value.substr(start) : value.substr(start, comma - start);
        chunk = trim_copy(chunk);
        if (!chunk.empty()) {
            out.push_back(chunk);
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return out;
}

} // namespace

DiscoveryManager::DiscoveryManager() : next_refresh_ms_(0) {}

bool DiscoveryManager::Initialize(const RouteSnapshot &snapshot,
                                  const DiscoveryConfig &config,
                                  std::string *error_out) {
    route_snapshot_ = snapshot;
    config_ = config;
    current_ = route_snapshot_.BuildInitialServiceSnapshot();
    next_refresh_ms_ = 0;

    if (!config_.enabled || config_.backend == DiscoveryConfig::Backend::Static || config_.path.empty()) {
        return true;
    }

    std::shared_ptr<ServiceSnapshot> next;
    if (!refresh_file_snapshot(&next, error_out)) {
        return false;
    }
    if (next) {
        current_ = next;
    }
    return true;
}

void DiscoveryManager::MaybeRefresh(uint64_t now_ms) {
    if (!config_.enabled || config_.backend == DiscoveryConfig::Backend::Static || config_.path.empty()) {
        return;
    }
    if (next_refresh_ms_ != 0 && now_ms < next_refresh_ms_) {
        return;
    }
    std::shared_ptr<ServiceSnapshot> next;
    std::string ignored;
    if (refresh_file_snapshot(&next, &ignored) && next) {
        current_ = next;
    }
    next_refresh_ms_ = now_ms + (config_.poll_ms > 0 ? config_.poll_ms : 1000ull);
}

std::shared_ptr<ServiceSnapshot> DiscoveryManager::Current() const {
    return current_;
}

int DiscoveryManager::WaitTimeoutMs() const {
    if (!config_.enabled || config_.backend == DiscoveryConfig::Backend::Static || config_.path.empty()) {
        return 1000;
    }
    const uint64_t poll_ms = config_.poll_ms > 0 ? config_.poll_ms : 1000ull;
    return static_cast<int>(poll_ms < 1000ull ? poll_ms : 1000ull);
}

bool DiscoveryManager::refresh_file_snapshot(std::shared_ptr<ServiceSnapshot> *next, std::string *error_out) const {
    if (next == nullptr) {
        return false;
    }

    std::ifstream input(config_.path.c_str());
    if (!input.is_open()) {
        if (error_out != nullptr) {
            *error_out = "failed to open discovery file: " + config_.path;
        }
        return false;
    }

    std::vector<ServiceDefinition> services = route_snapshot_.service_definitions();
    std::unordered_map<std::string, std::size_t> service_index;
    service_index.reserve(services.size());
    for (std::size_t i = 0; i < services.size(); ++i) {
        service_index[services[i].service] = i;
    }

    std::string line;
    while (std::getline(input, line)) {
        line = trim_copy(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) {
            if (error_out != nullptr) {
                *error_out = "invalid discovery file entry: " + line;
            }
            return false;
        }
        const std::string service = trim_copy(line.substr(0, eq));
        const std::string raw_targets = trim_copy(line.substr(eq + 1));
        if (service.empty()) {
            if (error_out != nullptr) {
                *error_out = "empty discovery service name";
            }
            return false;
        }
        std::unordered_map<std::string, std::size_t>::const_iterator it = service_index.find(service);
        if (it == service_index.end()) {
            continue;
        }
        std::vector<std::string> parsed_targets = split_targets(raw_targets);
        std::vector<UpstreamTarget> targets;
        targets.reserve(parsed_targets.size());
        for (std::size_t i = 0; i < parsed_targets.size(); ++i) {
            UpstreamTarget target;
            if (!parse_target_url(parsed_targets[i], &target)) {
                if (error_out != nullptr) {
                    *error_out = "invalid discovery target for service " + service + ": " + parsed_targets[i];
                }
                return false;
            }
            target.host_hash = fnv1a32(target.host.data(), target.host.size());
            populate_upstream_request_suffix(&target);
            if (!build_sockaddr(target.host.c_str(), target.port, &target.address, &target.address_len, error_out)) {
                return false;
            }
            target.address_ready = true;
            targets.push_back(target);
        }
        services[it->second].targets.swap(targets);
    }

    std::shared_ptr<ServiceSnapshot> snapshot = std::make_shared<ServiceSnapshot>();
    for (std::size_t i = 0; i < services.size(); ++i) {
        snapshot->Add(services[i]);
    }
    *next = snapshot;
    return true;
}

} // namespace core
} // namespace gateway
} // namespace kislay
