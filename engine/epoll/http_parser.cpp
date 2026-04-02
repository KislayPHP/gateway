#include "http_parser.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <strings.h>

namespace kislay {
namespace gateway {
namespace epoll {
namespace {

const char *kInvalidRequestLine = "invalid request line";
const char *kInvalidResponseLine = "invalid response line";
const char *kTooManyHeaders = "too many headers";
const char *kMalformedHeader = "malformed header";
const char *kHeaderTooLarge = "headers too large";
const char *kInvalidContentLength = "invalid content-length";

inline bool ieq(char a, char b) {
    return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
}

const char *find_header_end(const char *buffer, std::size_t length) {
    if (length < 4) {
        return nullptr;
    }
    for (std::size_t i = 0; i + 3 < length; ++i) {
        if (buffer[i] == '\r' && buffer[i + 1] == '\n' && buffer[i + 2] == '\r' && buffer[i + 3] == '\n') {
            return buffer + i + 4;
        }
    }
    return nullptr;
}

std::size_t trim_left(const char *buffer, std::size_t off, std::size_t end) {
    while (off < end && (buffer[off] == ' ' || buffer[off] == '\t')) {
        ++off;
    }
    return off;
}

std::size_t trim_right(const char *buffer, std::size_t off, std::size_t end) {
    while (end > off && (buffer[end - 1] == ' ' || buffer[end - 1] == '\t')) {
        --end;
    }
    return end;
}

bool parse_uint64(const char *buffer, std::size_t off, std::size_t len, uint64_t *out) {
    if (len == 0) {
        return false;
    }
    uint64_t value = 0;
    for (std::size_t i = 0; i < len; ++i) {
        const unsigned char ch = static_cast<unsigned char>(buffer[off + i]);
        if (ch < '0' || ch > '9') {
            return false;
        }
        value = (value * 10) + static_cast<uint64_t>(ch - '0');
    }
    *out = value;
    return true;
}

} // namespace

bool HeaderEquals(const char *buffer, const HeaderRef &header, const char *name) {
    const std::size_t name_len = std::strlen(name);
    if (header.name_len != name_len) {
        return false;
    }
    return strncasecmp(buffer + header.name_off, name, name_len) == 0;
}

bool HeaderValueContainsToken(const char *buffer, const HeaderRef &header, const char *token) {
    const std::size_t token_len = std::strlen(token);
    const char *value = buffer + header.value_off;
    const std::size_t value_len = header.value_len;
    if (token_len == 0 || token_len > value_len) {
        return false;
    }
    for (std::size_t i = 0; i + token_len <= value_len; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < token_len; ++j) {
            if (!ieq(value[i + j], token[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

ParseStatus ParseRequestHead(const char *buffer,
                            std::size_t length,
                            RequestHead *out,
                            HeaderRef *headers,
                            std::size_t max_headers,
                            const char **error_out) {
    const char *header_end = find_header_end(buffer, length);
    if (header_end == nullptr) {
        if (length >= 16384) {
            if (error_out) {
                *error_out = kHeaderTooLarge;
            }
            return ParseStatus::Error;
        }
        return ParseStatus::NeedMore;
    }

    const std::size_t headers_end = static_cast<std::size_t>(header_end - buffer);
    const char *line_end = static_cast<const char *>(std::memchr(buffer, '\n', headers_end));
    if (line_end == nullptr || line_end == buffer) {
        if (error_out) {
            *error_out = kInvalidRequestLine;
        }
        return ParseStatus::Error;
    }
    std::size_t request_line_end = static_cast<std::size_t>(line_end - buffer);
    if (request_line_end == 0 || buffer[request_line_end - 1] != '\r') {
        if (error_out) {
            *error_out = kInvalidRequestLine;
        }
        return ParseStatus::Error;
    }
    --request_line_end;

    std::size_t sp1 = 0;
    while (sp1 < request_line_end && buffer[sp1] != ' ') {
        ++sp1;
    }
    if (sp1 == 0 || sp1 >= request_line_end) {
        if (error_out) {
            *error_out = kInvalidRequestLine;
        }
        return ParseStatus::Error;
    }
    std::size_t sp2 = sp1 + 1;
    while (sp2 < request_line_end && buffer[sp2] != ' ') {
        ++sp2;
    }
    if (sp2 <= sp1 + 1 || sp2 >= request_line_end) {
        if (error_out) {
            *error_out = kInvalidRequestLine;
        }
        return ParseStatus::Error;
    }

    out->method_off = 0;
    out->method_len = static_cast<uint16_t>(sp1);

    const std::size_t target_off = sp1 + 1;
    const std::size_t target_len = sp2 - target_off;
    std::size_t query_rel = target_len;
    for (std::size_t i = 0; i < target_len; ++i) {
        if (buffer[target_off + i] == '?') {
            query_rel = i;
            break;
        }
    }
    out->path_off = static_cast<uint16_t>(target_off);
    out->path_len = static_cast<uint16_t>(query_rel);
    if (query_rel < target_len) {
        out->query_off = static_cast<uint16_t>(target_off + query_rel + 1);
        out->query_len = static_cast<uint16_t>(target_len - query_rel - 1);
    } else {
        out->query_off = 0;
        out->query_len = 0;
    }
    out->version_off = static_cast<uint16_t>(sp2 + 1);
    out->version_len = static_cast<uint16_t>(request_line_end - (sp2 + 1));
    out->headers_end = static_cast<uint16_t>(headers_end);
    out->header_count = 0;
    out->content_length = 0;
    out->has_content_length = false;
    out->chunked = false;
    out->keep_alive = true;
    out->no_body = false;

    if (out->version_len != 8 || std::memcmp(buffer + out->version_off, "HTTP/1.1", 8) != 0) {
        out->keep_alive = false;
    }

    std::size_t cursor = static_cast<std::size_t>((line_end - buffer) + 1);
    while (cursor + 1 < headers_end) {
        if (buffer[cursor] == '\r' && buffer[cursor + 1] == '\n') {
            break;
        }
        const char *next_end = static_cast<const char *>(std::memchr(buffer + cursor, '\n', headers_end - cursor));
        if (next_end == nullptr) {
            return ParseStatus::NeedMore;
        }
        std::size_t line_stop = static_cast<std::size_t>(next_end - buffer);
        if (line_stop == cursor || buffer[line_stop - 1] != '\r') {
            if (error_out) {
                *error_out = kMalformedHeader;
            }
            return ParseStatus::Error;
        }
        --line_stop;
        const char *colon_ptr = static_cast<const char *>(std::memchr(buffer + cursor, ':', line_stop - cursor));
        if (colon_ptr == nullptr) {
            if (error_out) {
                *error_out = kMalformedHeader;
            }
            return ParseStatus::Error;
        }
        if (out->header_count >= max_headers) {
            if (error_out) {
                *error_out = kTooManyHeaders;
            }
            return ParseStatus::Error;
        }
        std::size_t colon = static_cast<std::size_t>(colon_ptr - buffer);
        std::size_t name_off = cursor;
        std::size_t name_end = trim_right(buffer, name_off, colon);
        std::size_t value_off = trim_left(buffer, colon + 1, line_stop);
        std::size_t value_end = trim_right(buffer, value_off, line_stop);
        HeaderRef &header = headers[out->header_count++];
        header.name_off = static_cast<uint16_t>(name_off);
        header.name_len = static_cast<uint16_t>(name_end - name_off);
        header.value_off = static_cast<uint16_t>(value_off);
        header.value_len = static_cast<uint16_t>(value_end - value_off);

        if (HeaderEquals(buffer, header, "Content-Length")) {
            uint64_t parsed = 0;
            if (!parse_uint64(buffer, header.value_off, header.value_len, &parsed)) {
                if (error_out) {
                    *error_out = kInvalidContentLength;
                }
                return ParseStatus::Error;
            }
            out->content_length = parsed;
            out->has_content_length = true;
            out->no_body = parsed == 0;
        } else if (HeaderEquals(buffer, header, "Transfer-Encoding")) {
            if (HeaderValueContainsToken(buffer, header, "chunked")) {
                out->chunked = true;
            }
        } else if (HeaderEquals(buffer, header, "Connection")) {
            if (HeaderValueContainsToken(buffer, header, "close")) {
                out->keep_alive = false;
            } else if (HeaderValueContainsToken(buffer, header, "keep-alive")) {
                out->keep_alive = true;
            }
        }
        cursor = static_cast<std::size_t>((next_end - buffer) + 1);
    }

    if (out->chunked) {
        out->no_body = false;
    }
    return ParseStatus::Ok;
}

ParseStatus ParseResponseHead(const char *buffer,
                             std::size_t length,
                             ResponseHead *out,
                             HeaderRef *headers,
                             std::size_t max_headers,
                             const char **error_out) {
    const char *header_end = find_header_end(buffer, length);
    if (header_end == nullptr) {
        if (length >= 16384) {
            if (error_out) {
                *error_out = kHeaderTooLarge;
            }
            return ParseStatus::Error;
        }
        return ParseStatus::NeedMore;
    }

    const std::size_t headers_end = static_cast<std::size_t>(header_end - buffer);
    const char *line_end = static_cast<const char *>(std::memchr(buffer, '\n', headers_end));
    if (line_end == nullptr || line_end == buffer) {
        if (error_out) {
            *error_out = kInvalidResponseLine;
        }
        return ParseStatus::Error;
    }
    std::size_t status_line_end = static_cast<std::size_t>(line_end - buffer);
    if (status_line_end == 0 || buffer[status_line_end - 1] != '\r') {
        if (error_out) {
            *error_out = kInvalidResponseLine;
        }
        return ParseStatus::Error;
    }
    --status_line_end;

    std::size_t sp1 = 0;
    while (sp1 < status_line_end && buffer[sp1] != ' ') {
        ++sp1;
    }
    if (sp1 == 0 || sp1 + 4 > status_line_end) {
        if (error_out) {
            *error_out = kInvalidResponseLine;
        }
        return ParseStatus::Error;
    }
    out->version_off = 0;
    out->version_len = static_cast<uint16_t>(sp1);
    out->status_code = static_cast<uint16_t>(((buffer[sp1 + 1] - '0') * 100) +
                                             ((buffer[sp1 + 2] - '0') * 10) +
                                             (buffer[sp1 + 3] - '0'));
    out->reason_off = static_cast<uint16_t>((sp1 + 5 <= status_line_end) ? sp1 + 5 : status_line_end);
    out->reason_len = static_cast<uint16_t>((sp1 + 5 <= status_line_end) ? (status_line_end - (sp1 + 5)) : 0);
    out->headers_end = static_cast<uint16_t>(headers_end);
    out->header_count = 0;
    out->content_length = 0;
    out->has_content_length = false;
    out->chunked = false;
    out->keep_alive = true;
    out->no_body = (out->status_code >= 100 && out->status_code < 200) || out->status_code == 204 || out->status_code == 304;
    out->close_delimited = false;

    if (out->version_len != 8 || std::memcmp(buffer + out->version_off, "HTTP/1.1", 8) != 0) {
        out->keep_alive = false;
    }

    std::size_t cursor = static_cast<std::size_t>((line_end - buffer) + 1);
    while (cursor + 1 < headers_end) {
        if (buffer[cursor] == '\r' && buffer[cursor + 1] == '\n') {
            break;
        }
        const char *next_end = static_cast<const char *>(std::memchr(buffer + cursor, '\n', headers_end - cursor));
        if (next_end == nullptr) {
            return ParseStatus::NeedMore;
        }
        std::size_t line_stop = static_cast<std::size_t>(next_end - buffer);
        if (line_stop == cursor || buffer[line_stop - 1] != '\r') {
            if (error_out) {
                *error_out = kMalformedHeader;
            }
            return ParseStatus::Error;
        }
        --line_stop;
        const char *colon_ptr = static_cast<const char *>(std::memchr(buffer + cursor, ':', line_stop - cursor));
        if (colon_ptr == nullptr) {
            if (error_out) {
                *error_out = kMalformedHeader;
            }
            return ParseStatus::Error;
        }
        if (out->header_count >= max_headers) {
            if (error_out) {
                *error_out = kTooManyHeaders;
            }
            return ParseStatus::Error;
        }
        std::size_t colon = static_cast<std::size_t>(colon_ptr - buffer);
        std::size_t name_off = cursor;
        std::size_t name_end = trim_right(buffer, name_off, colon);
        std::size_t value_off = trim_left(buffer, colon + 1, line_stop);
        std::size_t value_end = trim_right(buffer, value_off, line_stop);
        HeaderRef &header = headers[out->header_count++];
        header.name_off = static_cast<uint16_t>(name_off);
        header.name_len = static_cast<uint16_t>(name_end - name_off);
        header.value_off = static_cast<uint16_t>(value_off);
        header.value_len = static_cast<uint16_t>(value_end - value_off);

        if (HeaderEquals(buffer, header, "Content-Length")) {
            uint64_t parsed = 0;
            if (!parse_uint64(buffer, header.value_off, header.value_len, &parsed)) {
                if (error_out) {
                    *error_out = kInvalidContentLength;
                }
                return ParseStatus::Error;
            }
            out->content_length = parsed;
            out->has_content_length = true;
        } else if (HeaderEquals(buffer, header, "Transfer-Encoding")) {
            if (HeaderValueContainsToken(buffer, header, "chunked")) {
                out->chunked = true;
            }
        } else if (HeaderEquals(buffer, header, "Connection")) {
            if (HeaderValueContainsToken(buffer, header, "close")) {
                out->keep_alive = false;
            } else if (HeaderValueContainsToken(buffer, header, "keep-alive")) {
                out->keep_alive = true;
            }
        }
        cursor = static_cast<std::size_t>((next_end - buffer) + 1);
    }

    if (!out->no_body && !out->has_content_length && !out->chunked) {
        out->close_delimited = true;
    }
    return ParseStatus::Ok;
}

} // namespace epoll
} // namespace gateway
} // namespace kislay
