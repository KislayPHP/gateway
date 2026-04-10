#include "timer_wheel.h"

#include <algorithm>

namespace kislay {
namespace gateway {
namespace core {

TimerWheel::TimerWheel() : tick_ms_(100), last_tick_ms_(0) {}

void TimerWheel::Initialize(std::size_t slot_count, uint64_t tick_ms) {
    if (slot_count == 0) {
        slot_count = 1024;
    }
    if (tick_ms == 0) {
        tick_ms = 100;
    }
    slots_.assign(slot_count, kNoIndex);
    tick_ms_ = tick_ms;
    last_tick_ms_ = 0;
}

void TimerWheel::Reset() {
    slots_.clear();
    tick_ms_ = 100;
    last_tick_ms_ = 0;
}

void TimerWheel::unlink(std::vector<Connection> *connections, uint32_t index) {
    if (connections == nullptr || index >= connections->size()) {
        return;
    }
    Connection &conn = (*connections)[index];
    if (!conn.timer_armed || conn.timer_slot == kNoIndex || conn.timer_slot >= slots_.size()) {
        conn.timer_prev = kNoIndex;
        conn.timer_next = kNoIndex;
        conn.timer_slot = kNoIndex;
        conn.timer_armed = false;
        return;
    }

    if (conn.timer_prev != kNoIndex) {
        (*connections)[conn.timer_prev].timer_next = conn.timer_next;
    } else {
        slots_[conn.timer_slot] = conn.timer_next;
    }
    if (conn.timer_next != kNoIndex) {
        (*connections)[conn.timer_next].timer_prev = conn.timer_prev;
    }

    conn.timer_prev = kNoIndex;
    conn.timer_next = kNoIndex;
    conn.timer_slot = kNoIndex;
    conn.timer_armed = false;
}

void TimerWheel::insert(std::vector<Connection> *connections, uint32_t index, uint64_t deadline_ms) {
    if (connections == nullptr || index >= connections->size() || slots_.empty()) {
        return;
    }
    Connection &conn = (*connections)[index];
    const uint64_t tick = deadline_ms / tick_ms_;
    const uint32_t slot = static_cast<uint32_t>(tick % slots_.size());
    conn.deadline_ms = deadline_ms;
    conn.timer_prev = kNoIndex;
    conn.timer_next = slots_[slot];
    conn.timer_slot = slot;
    conn.timer_armed = true;
    if (conn.timer_next != kNoIndex) {
        (*connections)[conn.timer_next].timer_prev = index;
    }
    slots_[slot] = index;
}

void TimerWheel::Arm(std::vector<Connection> *connections, uint32_t index, uint64_t deadline_ms) {
    if (connections == nullptr || index >= connections->size()) {
        return;
    }
    if ((*connections)[index].timer_armed) {
        unlink(connections, index);
    }
    insert(connections, index, deadline_ms);
}

void TimerWheel::Disarm(std::vector<Connection> *connections, uint32_t index) {
    if (connections == nullptr || index >= connections->size()) {
        return;
    }
    unlink(connections, index);
    (*connections)[index].deadline_ms = 0;
}

void TimerWheel::CollectExpired(std::vector<Connection> *connections, uint64_t now_ms, std::vector<uint32_t> *expired) {
    if (connections == nullptr || expired == nullptr || slots_.empty()) {
        return;
    }

    if (last_tick_ms_ == 0) {
        last_tick_ms_ = now_ms;
    }

    const uint64_t current_tick = now_ms / tick_ms_;
    uint64_t next_tick = last_tick_ms_ / tick_ms_;
    if (current_tick < next_tick) {
        next_tick = current_tick;
    }

    while (next_tick <= current_tick) {
        const uint32_t slot = static_cast<uint32_t>(next_tick % slots_.size());
        uint32_t index = slots_[slot];
        slots_[slot] = kNoIndex;
        while (index != kNoIndex) {
            Connection &conn = (*connections)[index];
            const uint32_t next = conn.timer_next;
            conn.timer_prev = kNoIndex;
            conn.timer_next = kNoIndex;
            conn.timer_slot = kNoIndex;
            conn.timer_armed = false;

            if (conn.in_use && conn.client_fd >= 0) {
                if (conn.deadline_ms <= now_ms) {
                    expired->push_back(index);
                } else {
                    insert(connections, index, conn.deadline_ms);
                }
            } else {
                conn.deadline_ms = 0;
            }

            index = next;
        }
        ++next_tick;
    }

    last_tick_ms_ = now_ms;
}

} // namespace core
} // namespace gateway
} // namespace kislay
