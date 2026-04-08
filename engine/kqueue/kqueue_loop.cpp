#include "kqueue_loop.h"

#include <cerrno>
#include <cstring>

#ifdef __APPLE__
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace kislay {
namespace gateway {
namespace platform {

#ifndef __APPLE__
KqueueLoop::KqueueLoop() : kqueue_fd_(-1) {}
KqueueLoop::~KqueueLoop() {}
bool KqueueLoop::Apply(int, uint32_t, uint64_t, std::string *error_out) {
    if (error_out != nullptr) {
        *error_out = "kqueue loop is macOS-only";
    }
    return false;
}
bool KqueueLoop::Add(int fd, uint32_t events, uint64_t token, std::string *error_out) { return Apply(fd, events, token, error_out); }
bool KqueueLoop::Modify(int fd, uint32_t events, uint64_t token, std::string *error_out) { return Apply(fd, events, token, error_out); }
void KqueueLoop::Remove(int) {}
int KqueueLoop::Wait(ReadyEvent *, int, int, std::string *error_out) {
    if (error_out != nullptr) {
        *error_out = "kqueue loop is macOS-only";
    }
    return -1;
}
bool KqueueLoop::SupportsSplice() const { return false; }
#else
namespace {
static void set_filter(struct kevent *change, int fd, int16_t filter, uint16_t flags, uint64_t token) {
    EV_SET(change, fd, filter, flags, 0, 0, reinterpret_cast<void *>(static_cast<uintptr_t>(token)));
}

static uint32_t from_kqueue_event(const struct kevent &event) {
    uint32_t generic = 0;
    if (event.filter == EVFILT_READ) generic |= kEventRead;
    if (event.filter == EVFILT_WRITE) generic |= kEventWrite;
    if ((event.flags & EV_EOF) != 0) generic |= kEventHangup;
    if ((event.flags & EV_ERROR) != 0) generic |= kEventError;
    return generic;
}
}

KqueueLoop::KqueueLoop() : kqueue_fd_(kqueue()) {}

KqueueLoop::~KqueueLoop() {
    if (kqueue_fd_ >= 0) {
        ::close(kqueue_fd_);
        kqueue_fd_ = -1;
    }
}

bool KqueueLoop::Apply(int fd, uint32_t events, uint64_t token, std::string *error_out) {
    if (kqueue_fd_ < 0) {
        if (error_out != nullptr) *error_out = std::strerror(errno);
        return false;
    }
    struct kevent changes[2];
    uint16_t read_flags = EV_ADD | EV_CLEAR;
    uint16_t write_flags = EV_ADD | EV_CLEAR;
    read_flags |= (events & kEventRead) ? EV_ENABLE : EV_DISABLE;
    write_flags |= (events & kEventWrite) ? EV_ENABLE : EV_DISABLE;
    set_filter(&changes[0], fd, EVFILT_READ, read_flags, token);
    set_filter(&changes[1], fd, EVFILT_WRITE, write_flags, token);
    if (kevent(kqueue_fd_, changes, 2, nullptr, 0, nullptr) == 0) {
        return true;
    }
    if (error_out != nullptr) {
        *error_out = std::strerror(errno);
    }
    return false;
}

bool KqueueLoop::Add(int fd, uint32_t events, uint64_t token, std::string *error_out) {
    return Apply(fd, events, token, error_out);
}

bool KqueueLoop::Modify(int fd, uint32_t events, uint64_t token, std::string *error_out) {
    return Apply(fd, events, token, error_out);
}

void KqueueLoop::Remove(int fd) {
    if (kqueue_fd_ < 0) {
        return;
    }
    struct kevent changes[2];
    set_filter(&changes[0], fd, EVFILT_READ, EV_DELETE, 0);
    set_filter(&changes[1], fd, EVFILT_WRITE, EV_DELETE, 0);
    kevent(kqueue_fd_, changes, 2, nullptr, 0, nullptr);
}

int KqueueLoop::Wait(ReadyEvent *events, int max_events, int timeout_ms, std::string *error_out) {
    if (kqueue_fd_ < 0) {
        if (error_out != nullptr) *error_out = std::strerror(errno);
        return -1;
    }
    struct timespec ts;
    ts.tv_sec = timeout_ms / 1000;
    ts.tv_nsec = (timeout_ms % 1000) * 1000000;
    struct kevent native_events[256];
    const int capped = max_events > 256 ? 256 : max_events;
    const int rc = kevent(kqueue_fd_, nullptr, 0, native_events, capped, &ts);
    if (rc < 0) {
        if (error_out != nullptr) {
            *error_out = std::strerror(errno);
        }
        return -1;
    }
    for (int i = 0; i < rc; ++i) {
        events[i].token = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(native_events[i].udata));
        events[i].events = from_kqueue_event(native_events[i]);
    }
    return rc;
}

bool KqueueLoop::SupportsSplice() const {
    return false;
}
#endif

} // namespace platform
} // namespace gateway
} // namespace kislay
