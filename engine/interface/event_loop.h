#pragma once

#include <cstdint>
#include <string>

namespace kislay {
namespace gateway {
namespace platform {

enum EventMask : uint32_t {
    kEventNone = 0,
    kEventRead = 1u << 0,
    kEventWrite = 1u << 1,
    kEventError = 1u << 2,
    kEventHangup = 1u << 3,
    kEventReadHup = 1u << 4,
    kEventEdge = 1u << 5,
};

struct ReadyEvent {
    uint64_t token;
    uint32_t events;
};

class EventLoop {
public:
    virtual ~EventLoop() {}

    virtual bool Add(int fd, uint32_t events, uint64_t token, std::string *error_out) = 0;
    virtual bool Modify(int fd, uint32_t events, uint64_t token, std::string *error_out) = 0;
    virtual void Remove(int fd) = 0;
    virtual int Wait(ReadyEvent *events, int max_events, int timeout_ms, std::string *error_out) = 0;
    virtual bool SupportsSplice() const = 0;
};

inline bool HasEvent(uint32_t events, uint32_t flag) {
    return (events & flag) != 0;
}

} // namespace platform
} // namespace gateway
} // namespace kislay
