#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace kislay {
namespace gateway {
namespace epoll {

struct UpstreamTarget {
    uint32_t host_hash;
    std::string host;
    uint16_t port;
    bool use_tls;
    std::string base_path;
    sockaddr_storage address;
    socklen_t address_len;
    bool address_ready;

    UpstreamTarget() : host_hash(0), port(0), use_tls(false), address_len(0), address_ready(false) {
        std::memset(&address, 0, sizeof(address));
    }
};

} // namespace epoll
} // namespace gateway
} // namespace kislay
