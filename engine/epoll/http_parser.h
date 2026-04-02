#pragma once

#include <cstddef>
#include <cstdint>

namespace kislay {
namespace gateway {
namespace epoll {

enum class ParseStatus {
    NeedMore = 0,
    Ok,
    Error,
};

struct HeaderRef {
    uint16_t name_off;
    uint16_t name_len;
    uint16_t value_off;
    uint16_t value_len;
};

struct RequestHead {
    uint16_t method_off;
    uint16_t method_len;
    uint16_t path_off;
    uint16_t path_len;
    uint16_t query_off;
    uint16_t query_len;
    uint16_t version_off;
    uint16_t version_len;
    uint16_t headers_end;
    uint16_t header_count;
    uint64_t content_length;
    bool has_content_length;
    bool chunked;
    bool keep_alive;
    bool no_body;
};

struct ResponseHead {
    uint16_t version_off;
    uint16_t version_len;
    uint16_t reason_off;
    uint16_t reason_len;
    uint16_t headers_end;
    uint16_t header_count;
    uint16_t status_code;
    uint64_t content_length;
    bool has_content_length;
    bool chunked;
    bool keep_alive;
    bool no_body;
    bool close_delimited;
};

ParseStatus ParseRequestHead(const char *buffer,
                            std::size_t length,
                            RequestHead *out,
                            HeaderRef *headers,
                            std::size_t max_headers,
                            const char **error_out);

ParseStatus ParseResponseHead(const char *buffer,
                             std::size_t length,
                             ResponseHead *out,
                             HeaderRef *headers,
                             std::size_t max_headers,
                             const char **error_out);

bool HeaderEquals(const char *buffer, const HeaderRef &header, const char *name);
bool HeaderValueContainsToken(const char *buffer, const HeaderRef &header, const char *token);

} // namespace epoll
} // namespace gateway
} // namespace kislay
