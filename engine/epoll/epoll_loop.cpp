#include "epoll_loop.h"

#include <cerrno>
#include <cstring>

#ifdef __linux__
#include <sys/epoll.h>
#include <unistd.h>
#endif

namespace kislay {
namespace gateway {
namespace platform {

#ifndef __linux__
EpollLoop::EpollLoop() : epoll_fd_(-1) {}
EpollLoop::~EpollLoop() {}
bool EpollLoop::Add(int, uint32_t, uint64_t, std::string *error_out) {
    if (error_out != nullptr) {
        *error_out = "epoll loop is Linux-only";
    }
    return false;
}
bool EpollLoop::Modify(int, uint32_t, uint64_t, std::string *error_out) {
    if (error_out != nullptr) {
        *error_out = "epoll loop is Linux-only";
    }
    return false;
}
void EpollLoop::Remove(int) {}
int EpollLoop::Wait(ReadyEvent *, int, int, std::string *error_out) {
    if (error_out != nullptr) {
        *error_out = "epoll loop is Linux-only";
    }
    return -1;
}
bool EpollLoop::SupportsSplice() const { return false; }
#else
namespace {
static uint32_t to_epoll_events(uint32_t events) {
    uint32_t native = 0;
    if (events & kEventRead) native |= EPOLLIN;
    if (events & kEventWrite) native |= EPOLLOUT;
    if (events & kEventEdge) native |= EPOLLET;
    if (events & kEventReadHup) native |= EPOLLRDHUP;
    return native;
}

static uint32_t from_epoll_events(uint32_t events) {
    uint32_t generic = 0;
    if (events & EPOLLIN) generic |= kEventRead;
    if (events & EPOLLOUT) generic |= kEventWrite;
    if (events & EPOLLERR) generic |= kEventError;
    if (events & EPOLLHUP) generic |= kEventHangup;
    if (events & EPOLLRDHUP) generic |= kEventReadHup;
    return generic;
}

static bool epoll_ctl_apply(int epoll_fd, int op, int fd, uint32_t events, uint64_t token, std::string *error_out) {
    struct epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = to_epoll_events(events);
    ev.data.u64 = token;
    if (epoll_ctl(epoll_fd, op, fd, &ev) == 0) {
        return true;
    }
    if (error_out != nullptr) {
        *error_out = std::strerror(errno);
    }
    return false;
}
}

EpollLoop::EpollLoop() : epoll_fd_(epoll_create1(0)) {}

EpollLoop::~EpollLoop() {
    if (epoll_fd_ >= 0) {
        ::close(epoll_fd_);
        epoll_fd_ = -1;
    }
}

bool EpollLoop::Add(int fd, uint32_t events, uint64_t token, std::string *error_out) {
    if (epoll_fd_ < 0) {
        if (error_out != nullptr) *error_out = std::strerror(errno);
        return false;
    }
    return epoll_ctl_apply(epoll_fd_, EPOLL_CTL_ADD, fd, events, token, error_out);
}

bool EpollLoop::Modify(int fd, uint32_t events, uint64_t token, std::string *error_out) {
    if (epoll_fd_ < 0) {
        if (error_out != nullptr) *error_out = std::strerror(errno);
        return false;
    }
    return epoll_ctl_apply(epoll_fd_, EPOLL_CTL_MOD, fd, events, token, error_out);
}

void EpollLoop::Remove(int fd) {
    if (epoll_fd_ >= 0) {
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    }
}

int EpollLoop::Wait(ReadyEvent *events, int max_events, int timeout_ms, std::string *error_out) {
    if (epoll_fd_ < 0) {
        if (error_out != nullptr) *error_out = std::strerror(errno);
        return -1;
    }
    struct epoll_event native_events[256];
    const int capped = max_events > 256 ? 256 : max_events;
    const int rc = epoll_wait(epoll_fd_, native_events, capped, timeout_ms);
    if (rc < 0) {
        if (error_out != nullptr) {
            *error_out = std::strerror(errno);
        }
        return -1;
    }
    for (int i = 0; i < rc; ++i) {
        events[i].token = native_events[i].data.u64;
        events[i].events = from_epoll_events(native_events[i].events);
    }
    return rc;
}

bool EpollLoop::SupportsSplice() const {
    return true;
}
#endif

} // namespace platform
} // namespace gateway
} // namespace kislay
