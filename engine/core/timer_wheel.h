#pragma once

#include "connection.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kislay {
namespace gateway {
namespace core {

class TimerWheel {
public:
    enum : uint32_t { kNoIndex = UINT32_MAX };

    TimerWheel();

    void Initialize(std::size_t slot_count, uint64_t tick_ms);
    void Reset();
    void Arm(std::vector<Connection> *connections, uint32_t index, uint64_t deadline_ms);
    void Disarm(std::vector<Connection> *connections, uint32_t index);
    void CollectExpired(std::vector<Connection> *connections, uint64_t now_ms, std::vector<uint32_t> *expired);

private:
    void insert(std::vector<Connection> *connections, uint32_t index, uint64_t deadline_ms);
    void unlink(std::vector<Connection> *connections, uint32_t index);

    std::vector<uint32_t> slots_;
    uint64_t tick_ms_;
    uint64_t last_tick_ms_;
};

} // namespace core
} // namespace gateway
} // namespace kislay
