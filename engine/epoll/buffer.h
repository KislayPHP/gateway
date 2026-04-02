#pragma once

#include <array>
#include <cstddef>
#include <cstring>

namespace kislay {
namespace gateway {
namespace epoll {

template <std::size_t Capacity>
struct FixedBuffer {
    std::array<char, Capacity> storage;
    std::size_t start;
    std::size_t end;

    FixedBuffer() : start(0), end(0) {}

    void clear() {
        start = 0;
        end = 0;
    }

    std::size_t readable() const {
        return end - start;
    }

    std::size_t writable() const {
        return Capacity - end;
    }

    bool empty() const {
        return start == end;
    }

    char *write_ptr() {
        return storage.data() + end;
    }

    const char *read_ptr() const {
        return storage.data() + start;
    }

    char *data() {
        return storage.data();
    }

    const char *data() const {
        return storage.data();
    }

    void produced(std::size_t bytes) {
        end += bytes;
    }

    void consumed(std::size_t bytes) {
        start += bytes;
        if (start >= end) {
            clear();
        }
    }

    void compact() {
        if (start == 0) {
            return;
        }
        if (start == end) {
            clear();
            return;
        }
        std::memmove(storage.data(), storage.data() + start, end - start);
        end -= start;
        start = 0;
    }

    void compact_if_needed(std::size_t need = 1) {
        if (writable() >= need) {
            return;
        }
        compact();
    }
};

} // namespace epoll
} // namespace gateway
} // namespace kislay
