#pragma once

#include "../interface/event_loop.h"

namespace kislay {
namespace gateway {
namespace platform {

class KqueueLoop : public EventLoop {
public:
    KqueueLoop();
    ~KqueueLoop() override;

    bool Add(int fd, uint32_t events, uint64_t token, std::string *error_out) override;
    bool Modify(int fd, uint32_t events, uint64_t token, std::string *error_out) override;
    void Remove(int fd) override;
    int Wait(ReadyEvent *events, int max_events, int timeout_ms, std::string *error_out) override;
    bool SupportsSplice() const override;

private:
    bool Apply(int fd, uint32_t events, uint64_t token, std::string *error_out);
    int kqueue_fd_;
};

} // namespace platform
} // namespace gateway
} // namespace kislay
