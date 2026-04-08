#pragma once

#include "../interface/event_loop.h"

namespace kislay {
namespace gateway {
namespace platform {

class EpollLoop : public EventLoop {
public:
    EpollLoop();
    ~EpollLoop() override;

    bool Add(int fd, uint32_t events, uint64_t token, std::string *error_out) override;
    bool Modify(int fd, uint32_t events, uint64_t token, std::string *error_out) override;
    void Remove(int fd) override;
    int Wait(ReadyEvent *events, int max_events, int timeout_ms, std::string *error_out) override;
    bool SupportsSplice() const override;

private:
    int epoll_fd_;
};

} // namespace platform
} // namespace gateway
} // namespace kislay
