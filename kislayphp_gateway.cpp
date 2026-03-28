extern "C" {
#include "php.h"
#include "ext/standard/info.h"
#include "Zend/zend_exceptions.h"
}

#include "php_kislayphp_gateway.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <chrono>
#include <civetweb.h>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <strings.h>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef KISLAYPHP_RPC
#include <grpcpp/grpcpp.h>

#include "discovery.grpc.pb.h"
#endif

static zend_class_entry *kislayphp_gateway_ce;

struct kislayphp_gateway_route {
    std::string method;
    std::string path;
    std::string target;
    std::string service;
    bool use_service;
    std::string host;
    int port;
    bool use_tls;
    std::string base_path;
};

struct kislayphp_rate_limit_entry {
    std::time_t window_start;
    zend_long count;
};

struct kislayphp_circuit_state {
    zend_long failures;
    std::time_t open_until;
    bool half_open_in_flight;
};

struct kislayphp_upstream_pool {
    std::unordered_map<std::string, struct mg_connection *> idle;

    ~kislayphp_upstream_pool() {
        for (auto &entry : idle) {
            if (entry.second != nullptr) {
                mg_close_connection(entry.second);
            }
        }
    }

    struct mg_connection *take(const std::string &key) {
        auto it = idle.find(key);
        if (it == idle.end()) {
            return nullptr;
        }
        struct mg_connection *conn = it->second;
        idle.erase(it);
        return conn;
    }

    void put(const std::string &key, struct mg_connection *conn) {
        if (conn == nullptr) {
            return;
        }
        auto it = idle.find(key);
        if (it != idle.end() && it->second != nullptr) {
            mg_close_connection(it->second);
        }
        idle[key] = conn;
    }
};

typedef struct _php_kislayphp_gateway_t {
    std::vector<kislayphp_gateway_route> routes;
    kislayphp_gateway_route fallback_route;
    bool has_fallback;
    std::mutex lock;
    struct mg_context *ctx;
    bool running;
    size_t max_body_bytes;
    int thread_count;
    zval resolver;
    bool has_resolver;
    bool auth_required;
    std::string auth_bearer_token;
    std::vector<std::string> auth_exclude_prefixes;
    std::string jwt_secret;
    std::string auth_user_header;
    zend_long proxy_read_timeout_ms;
    zend_long proxy_retries;
    bool rate_limit_enabled;
    zend_long rate_limit_requests;
    zend_long rate_limit_window_seconds;
    std::unordered_map<std::string, kislayphp_rate_limit_entry> rate_limits;
    bool circuit_breaker_enabled;
    zend_long circuit_failure_threshold;
    zend_long circuit_open_seconds;
    std::unordered_map<std::string, kislayphp_circuit_state> circuit_states;
    zend_object std;
} php_kislayphp_gateway_t;

static zend_object_handlers kislayphp_gateway_handlers;

static kislayphp_upstream_pool &kislayphp_gateway_upstream_pool() {
    static thread_local kislayphp_upstream_pool pool;
    return pool;
}

static std::string kislayphp_client_identifier(const struct mg_request_info *info);

static zend_long kislayphp_env_long(const char *name, zend_long fallback) {
    const char *value = std::getenv(name);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }
    return static_cast<zend_long>(std::strtoll(value, nullptr, 10));
}

static bool kislayphp_is_hop_header(const char *name) {
    if (name == nullptr) {
        return false;
    }
    if (::strcasecmp(name, "Connection") == 0) {
        return true;
    }
    if (::strcasecmp(name, "Proxy-Connection") == 0) {
        return true;
    }
    if (::strcasecmp(name, "Keep-Alive") == 0) {
        return true;
    }
    if (::strcasecmp(name, "TE") == 0) {
        return true;
    }
    if (::strcasecmp(name, "Trailer") == 0) {
        return true;
    }
    if (::strcasecmp(name, "Transfer-Encoding") == 0) {
        return true;
    }
    if (::strcasecmp(name, "Upgrade") == 0) {
        return true;
    }
    return false;
}

static bool kislayphp_env_bool(const char *name, bool fallback) {
    const char *value = std::getenv(name);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }
    if (::strcasecmp(value, "1") == 0 || ::strcasecmp(value, "true") == 0 ||
        ::strcasecmp(value, "yes") == 0 || ::strcasecmp(value, "on") == 0) {
        return true;
    }
    if (::strcasecmp(value, "0") == 0 || ::strcasecmp(value, "false") == 0 ||
        ::strcasecmp(value, "no") == 0 || ::strcasecmp(value, "off") == 0) {
        return false;
    }
    return fallback;
}

static std::string kislayphp_env_string(const char *name, const char *fallback) {
    const char *value = std::getenv(name);
    if (value == nullptr || *value == '\0') {
        return std::string(fallback ? fallback : "");
    }
    return std::string(value);
}

static void kislayphp_disable_stack_guard_for_nts(const char *source) {
    (void) source;
#if !defined(ZTS) && PHP_VERSION_ID >= 80300
    /* max_allowed_stack_size / stack_limit added in PHP 8.3 */
    EG(max_allowed_stack_size) = -1;
    EG(stack_limit) = nullptr;
#endif
}

static int kislayphp_sanitize_thread_count(int requested, const char *source) {
    if (requested < 1) {
        php_error_docref(nullptr, E_WARNING, "%s: invalid thread count %d; using 1", source, requested);
        return 1;
    }
#if !defined(ZTS)
    if (requested > 1) {
        php_error_docref(nullptr, E_WARNING, "%s: Thread Safety is disabled; forcing num_threads=1", source);
        return 1;
    }
#endif
    return requested;
}

#ifdef KISLAYPHP_RPC
static bool kislayphp_rpc_enabled() {
    return kislayphp_env_bool("KISLAY_RPC_ENABLED", false);
}

static zend_long kislayphp_rpc_timeout_ms() {
    zend_long timeout = kislayphp_env_long("KISLAY_RPC_TIMEOUT_MS", 200);
    return timeout > 0 ? timeout : 200;
}

static std::string kislayphp_rpc_discovery_endpoint() {
    return kislayphp_env_string("KISLAY_RPC_DISCOVERY_ENDPOINT", "127.0.0.1:9090");
}

static kislay::discovery::v1::DiscoveryService::Stub *kislayphp_rpc_discovery_stub(const std::string &endpoint) {
    static std::mutex lock;
    static std::string cached_endpoint;
    static std::shared_ptr<grpc::Channel> channel;
    static std::unique_ptr<kislay::discovery::v1::DiscoveryService::Stub> stub;
    std::lock_guard<std::mutex> guard(lock);
    if (!stub || cached_endpoint != endpoint) {
        channel = grpc::CreateChannel(endpoint, grpc::InsecureChannelCredentials());
        stub = kislay::discovery::v1::DiscoveryService::NewStub(channel);
        cached_endpoint = endpoint;
    }
    return stub.get();
}

static bool kislayphp_rpc_resolve_service(const std::string &service, std::string *target, std::string *error) {
    auto *stub = kislayphp_rpc_discovery_stub(kislayphp_rpc_discovery_endpoint());
    if (!stub) {
        if (error) {
            *error = "RPC stub unavailable";
        }
        return false;
    }

    kislay::discovery::v1::ResolveRequest request;
    request.set_service_name(service);
    kislay::discovery::v1::ResolveResponse response;
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(kislayphp_rpc_timeout_ms()));

    grpc::Status status = stub->Resolve(&context, request, &response);
    if (!status.ok()) {
        if (error) {
            *error = status.error_message();
        }
        return false;
    }
    if (!response.ok()) {
        if (error) {
            *error = response.error();
        }
        return false;
    }
    if (target) {
        *target = response.instance().url();
    }
    return true;
}
#endif

static std::string kislayphp_trim(const std::string &value) {
    size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start])) != 0) {
        ++start;
    }
    size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    return value.substr(start, end - start);
}

static std::vector<std::string> kislayphp_split_csv(const std::string &csv) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= csv.size()) {
        size_t comma = csv.find(',', start);
        std::string chunk = (comma == std::string::npos)
            ? csv.substr(start)
            : csv.substr(start, comma - start);
        chunk = kislayphp_trim(chunk);
        if (!chunk.empty()) {
            out.push_back(chunk);
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return out;
}

static const char *kislayphp_get_header(const struct mg_request_info *info, const char *name) {
    if (info == nullptr || name == nullptr) {
        return nullptr;
    }
    for (int i = 0; i < info->num_headers; ++i) {
        const char *hname = info->http_headers[i].name;
        const char *hvalue = info->http_headers[i].value;
        if (hname == nullptr || hvalue == nullptr) {
            continue;
        }
        if (::strcasecmp(hname, name) == 0) {
            return hvalue;
        }
    }
    return nullptr;
}

static bool kislayphp_header_has_token(const char *value, const char *token) {
    if (value == nullptr || token == nullptr) {
        return false;
    }

    std::string haystack(value);
    std::string needle(token);
    std::transform(haystack.begin(), haystack.end(), haystack.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    size_t start = 0;
    while (start <= haystack.size()) {
        size_t comma = haystack.find(',', start);
        std::string chunk = comma == std::string::npos
            ? haystack.substr(start)
            : haystack.substr(start, comma - start);
        chunk = kislayphp_trim(chunk);
        if (chunk == needle) {
            return true;
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return false;
}

static bool kislayphp_response_header_has_token(const struct mg_response_info *resp_info,
                                                const char *name,
                                                const char *token) {
    if (resp_info == nullptr) {
        return false;
    }
    for (int i = 0; i < resp_info->num_headers; ++i) {
        const char *hname = resp_info->http_headers[i].name;
        const char *hvalue = resp_info->http_headers[i].value;
        if (hname == nullptr || hvalue == nullptr) {
            continue;
        }
        if (::strcasecmp(hname, name) == 0) {
            return kislayphp_header_has_token(hvalue, token);
        }
    }
    return false;
}

static std::string kislayphp_request_forwarded_for(const struct mg_request_info *info) {
    std::string client = kislayphp_client_identifier(info);
    const char *existing = kislayphp_get_header(info, "X-Forwarded-For");
    if (existing == nullptr || *existing == '\0') {
        return client;
    }
    std::string combined(existing);
    if (!combined.empty()) {
        combined.append(", ");
    }
    combined.append(client);
    return combined;
}

static std::string kislayphp_request_forwarded_proto(const struct mg_request_info *info) {
    const char *existing = kislayphp_get_header(info, "X-Forwarded-Proto");
    if (existing != nullptr && *existing != '\0') {
        return std::string(existing);
    }
    return (info != nullptr && info->is_ssl) ? "https" : "http";
}

static std::string kislayphp_request_forwarded_host(const struct mg_request_info *info) {
    const char *existing = kislayphp_get_header(info, "X-Forwarded-Host");
    if (existing != nullptr && *existing != '\0') {
        return std::string(existing);
    }
    const char *host = kislayphp_get_header(info, "Host");
    if (host != nullptr && *host != '\0') {
        return std::string(host);
    }
    return "unknown";
}

static std::string kislayphp_upstream_key(const kislayphp_gateway_route &route) {
    return std::string(route.use_tls ? "https://" : "http://")
        + route.host + ":" + std::to_string(route.port);
}

static bool kislayphp_can_reuse_upstream_response(const struct mg_response_info *resp_info) {
    if (resp_info == nullptr) {
        return false;
    }
    if (kislayphp_response_header_has_token(resp_info, "Connection", "close")) {
        return false;
    }
    if (resp_info->content_length >= 0) {
        return true;
    }
    return kislayphp_response_header_has_token(resp_info, "Transfer-Encoding", "chunked");
}

static bool kislayphp_has_prefix(const std::string &value, const std::string &prefix) {
    if (prefix.empty()) {
        return false;
    }
    if (value.size() < prefix.size()) {
        return false;
    }
    return value.compare(0, prefix.size(), prefix) == 0;
}

static std::string kislayphp_client_identifier(const struct mg_request_info *info) {
    const char *forwarded = kislayphp_get_header(info, "X-Forwarded-For");
    if (forwarded != nullptr && *forwarded != '\0') {
        std::string s = forwarded;
        size_t comma = s.find(',');
        if (comma != std::string::npos) {
            return kislayphp_trim(s.substr(0, comma));
        }
        return kislayphp_trim(s);
    }
    if (info->remote_addr != nullptr) {
        return std::string(info->remote_addr);
    }
    return "unknown";
}

static inline php_kislayphp_gateway_t *php_kislayphp_gateway_from_obj(zend_object *obj) {
    return reinterpret_cast<php_kislayphp_gateway_t *>(
        reinterpret_cast<char *>(obj) - XtOffsetOf(php_kislayphp_gateway_t, std));
}

static zend_object *kislayphp_gateway_create_object(zend_class_entry *ce) {
    php_kislayphp_gateway_t *obj = static_cast<php_kislayphp_gateway_t *>(
        ecalloc(1, sizeof(php_kislayphp_gateway_t) + zend_object_properties_size(ce)));
    zend_object_std_init(&obj->std, ce);
    object_properties_init(&obj->std, ce);
    new (&obj->routes) std::vector<kislayphp_gateway_route>();
    new (&obj->fallback_route) kislayphp_gateway_route();
    new (&obj->lock) std::mutex();
    new (&obj->auth_bearer_token) std::string();
    new (&obj->auth_exclude_prefixes) std::vector<std::string>();
    new (&obj->jwt_secret) std::string();
    new (&obj->auth_user_header) std::string();
    new (&obj->rate_limits) std::unordered_map<std::string, kislayphp_rate_limit_entry>();
    new (&obj->circuit_states) std::unordered_map<std::string, kislayphp_circuit_state>();
    obj->ctx = nullptr;
    obj->running = false;
    obj->has_fallback = false;
    zend_long max_body = kislayphp_env_long("KISLAY_GATEWAY_MAX_BODY", 0);
    if (max_body < 0) {
        max_body = 0;
    }
    obj->max_body_bytes = static_cast<size_t>(max_body);
    zend_long threads = kislayphp_env_long("KISLAY_GATEWAY_THREADS", 1);
    obj->thread_count = kislayphp_sanitize_thread_count(static_cast<int>(threads), "Kislay\\Gateway\\Gateway::__construct");
    ZVAL_UNDEF(&obj->resolver);
    obj->has_resolver = false;
    obj->auth_required = kislayphp_env_bool("KISLAY_GATEWAY_AUTH_REQUIRED", false);
    obj->auth_bearer_token = kislayphp_env_string("KISLAY_GATEWAY_AUTH_TOKEN", "");
    obj->auth_exclude_prefixes = kislayphp_split_csv(
        kislayphp_env_string("KISLAY_GATEWAY_AUTH_EXCLUDE", "/health,/ready,/metrics"));
    obj->jwt_secret = kislayphp_env_string("KISLAY_GATEWAY_JWT_SECRET", "");
    obj->auth_user_header = "X-Authenticated-User";
    obj->proxy_read_timeout_ms = kislayphp_env_long("KISLAY_GATEWAY_READ_TIMEOUT_MS", 10000);
    if (obj->proxy_read_timeout_ms < 1) {
        obj->proxy_read_timeout_ms = 10000;
    }
    obj->proxy_retries = kislayphp_env_long("KISLAY_GATEWAY_RETRY_IDEMPOTENT", 1);
    if (obj->proxy_retries < 0) {
        obj->proxy_retries = 0;
    }
    obj->rate_limit_enabled = kislayphp_env_bool("KISLAY_GATEWAY_RATE_LIMIT_ENABLED", false);
    obj->rate_limit_requests = kislayphp_env_long("KISLAY_GATEWAY_RATE_LIMIT_REQUESTS", 120);
    if (obj->rate_limit_requests < 1) {
        obj->rate_limit_requests = 1;
    }
    obj->rate_limit_window_seconds = kislayphp_env_long("KISLAY_GATEWAY_RATE_LIMIT_WINDOW", 60);
    if (obj->rate_limit_window_seconds < 1) {
        obj->rate_limit_window_seconds = 1;
    }
    obj->circuit_breaker_enabled = kislayphp_env_bool("KISLAY_GATEWAY_CIRCUIT_BREAKER_ENABLED", false);
    obj->circuit_failure_threshold = kislayphp_env_long("KISLAY_GATEWAY_CB_FAILURE_THRESHOLD", 5);
    if (obj->circuit_failure_threshold < 1) {
        obj->circuit_failure_threshold = 1;
    }
    obj->circuit_open_seconds = kislayphp_env_long("KISLAY_GATEWAY_CB_OPEN_SECONDS", 30);
    if (obj->circuit_open_seconds < 1) {
        obj->circuit_open_seconds = 1;
    }
    obj->std.handlers = &kislayphp_gateway_handlers;
    return &obj->std;
}

static void kislayphp_gateway_free_obj(zend_object *object) {
    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(object);
    if (obj->ctx != nullptr) {
        mg_stop(obj->ctx);
        obj->ctx = nullptr;
    }
    if (obj->has_resolver) {
        zval_ptr_dtor(&obj->resolver);
    }
    obj->circuit_states.~unordered_map();
    obj->rate_limits.~unordered_map();
    obj->auth_user_header.~basic_string();
    obj->jwt_secret.~basic_string();
    obj->auth_exclude_prefixes.~vector();
    obj->auth_bearer_token.~basic_string();
    obj->routes.~vector();
    obj->fallback_route.~kislayphp_gateway_route();
    obj->lock.~mutex();
    zend_object_std_dtor(&obj->std);
}

static std::string kislayphp_to_upper(const std::string &value) {
    std::string out = value;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return out;
}

static std::string kislayphp_exception_debug_string() {
    if (EG(exception) == nullptr) {
        return "";
    }
    zend_object *exception = EG(exception);
    std::string class_name = exception->ce != nullptr
        ? std::string(ZSTR_VAL(exception->ce->name))
        : "Exception";
    zval rv_message;
    zval *message = zend_read_property(exception->ce, exception, ZEND_STRL("message"), 1, &rv_message);
    std::string out = class_name;
    if (message != nullptr && Z_TYPE_P(message) == IS_STRING && Z_STRLEN_P(message) > 0) {
        out += ": " + std::string(Z_STRVAL_P(message), Z_STRLEN_P(message));
    }
    return out;
}

static std::string kislayphp_join_paths(const std::string &base, const std::string &path) {
    if (base.empty()) {
        return path.empty() ? std::string("/") : path;
    }
    if (path.empty()) {
        return base;
    }
    if (base.back() == '/' && path.front() == '/') {
        return base + path.substr(1);
    }
    if (base.back() != '/' && path.front() != '/') {
        return base + "/" + path;
    }
    return base + path;
}

static bool kislayphp_path_matches(const std::string &pattern, const std::string &path) {
    if (pattern.empty()) {
        return path.empty() || path == "/";
    }
    if (pattern == path) {
        return true;
    }
    if (pattern.back() != '*') {
        return false;
    }
    std::string prefix = pattern.substr(0, pattern.size() - 1);
    if (prefix.empty()) {
        return true;
    }
    if (path.size() < prefix.size()) {
        return false;
    }
    return path.compare(0, prefix.size(), prefix) == 0;
}

static bool kislayphp_parse_target(const std::string &target, kislayphp_gateway_route &route) {
    std::string value = target;
    const std::string http_prefix = "http://";
    const std::string https_prefix = "https://";
    bool use_tls = false;
    if (value.rfind(http_prefix, 0) == 0) {
        value = value.substr(http_prefix.size());
    } else if (value.rfind(https_prefix, 0) == 0) {
        value = value.substr(https_prefix.size());
        use_tls = true;
    }

    std::string hostport;
    std::string base_path = "/";
    size_t slash = value.find('/');
    if (slash == std::string::npos) {
        hostport = value;
    } else {
        hostport = value.substr(0, slash);
        base_path = value.substr(slash);
    }

    if (hostport.empty()) {
        return false;
    }

    std::string host = hostport;
    int port = use_tls ? 443 : 80;
    size_t colon = hostport.find(':');
    if (colon != std::string::npos) {
        host = hostport.substr(0, colon);
        std::string port_str = hostport.substr(colon + 1);
        if (port_str.empty()) {
            return false;
        }
        port = std::atoi(port_str.c_str());
        if (port <= 0) {
            return false;
        }
    }

    route.host = host;
    route.port = port;
    route.use_tls = use_tls;
    route.base_path = base_path;
    return true;
}

static bool kislayphp_call_php(zval *callable, uint32_t argc, zval *argv, zval *retval, std::string *error_out = nullptr) {
    ZVAL_UNDEF(retval);
    if (call_user_function(EG(function_table), nullptr, callable, retval, argc, argv) == FAILURE) {
        if (error_out != nullptr) {
            *error_out = "call_user_function failed";
            std::string exception_text = kislayphp_exception_debug_string();
            if (!exception_text.empty()) {
                *error_out += " (" + exception_text + ")";
            }
        }
        return false;
    }
    if (error_out != nullptr && EG(exception) != nullptr) {
        *error_out = "exception in callback (" + kislayphp_exception_debug_string() + ")";
    }
    return true;
}

static void kislayphp_send_error(struct mg_connection *conn, int status, const char *message) {
    const char *status_text = "Error";
    if (status == 401) {
        status_text = "Unauthorized";
    } else if (status == 404) {
        status_text = "Not Found";
    } else if (status == 413) {
        status_text = "Payload Too Large";
    } else if (status == 429) {
        status_text = "Too Many Requests";
    } else if (status == 502) {
        status_text = "Bad Gateway";
    } else if (status == 503) {
        status_text = "Service Unavailable";
    }
    mg_printf(conn,
              "HTTP/1.1 %d %s\r\n"
              "Content-Type: text/plain; charset=utf-8\r\n"
              "Content-Length: %zu\r\n"
              "Connection: close\r\n\r\n"
              "%s",
              status,
              status_text,
              std::strlen(message),
              message);
}

// ─────────────────────────────────────────────────────────────────────────────
// JWT helpers (HS256, no external library beyond OpenSSL)
// ─────────────────────────────────────────────────────────────────────────────

static bool kislay_gateway_base64url_decode(const std::string &in, std::string &out) {
    static const std::string b64chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string padded = in;
    std::replace(padded.begin(), padded.end(), '-', '+');
    std::replace(padded.begin(), padded.end(), '_', '/');
    switch (padded.size() % 4) {
        case 2: padded += "=="; break;
        case 3: padded += "=";  break;
        default: break;
    }
    out.clear();
    int val = 0, valb = -8;
    for (unsigned char c : padded) {
        if (c == '=') break;
        size_t pos = b64chars.find(static_cast<char>(c));
        if (pos == std::string::npos) return false;
        val = (val << 6) + static_cast<int>(pos);
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return true;
}

static bool kislay_gateway_path_excluded(const std::string &path,
                                         const std::vector<std::string> &excludes) {
    for (const auto &prefix : excludes) {
        if (kislayphp_has_prefix(path, prefix)) {
            return true;
        }
    }
    return false;
}

static bool kislay_gateway_validate_jwt(const std::string &token,
                                        const std::string &secret) {

    size_t dot1 = token.find('.');
    if (dot1 == std::string::npos) return false;
    size_t dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return false;

    std::string header_b64  = token.substr(0, dot1);
    std::string payload_b64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
    std::string sig_b64     = token.substr(dot2 + 1);

    // Verify algorithm claim
    std::string header_json;
    if (!kislay_gateway_base64url_decode(header_b64, header_json)) return false;
    if (header_json.find("\"HS256\"") == std::string::npos) return false;

    // Decode payload
    std::string payload_json;
    if (!kislay_gateway_base64url_decode(payload_b64, payload_json)) return false;

    // Check exp claim
    size_t exp_pos = payload_json.find("\"exp\"");
    if (exp_pos != std::string::npos) {
        size_t colon = payload_json.find(':', exp_pos + 5);
        if (colon != std::string::npos) {
            size_t num_start = payload_json.find_first_of("0123456789", colon + 1);
            if (num_start != std::string::npos) {
                size_t num_end = payload_json.find_first_not_of("0123456789", num_start);
                std::string num_str = payload_json.substr(num_start,
                    num_end == std::string::npos ? std::string::npos : num_end - num_start);
                long long exp_val = std::stoll(num_str);
                if (exp_val < static_cast<long long>(std::time(nullptr))) {
                    return false;
                }
            }
        }
    }

    // Verify HMAC-SHA256 signature
    std::string signing_input = header_b64 + "." + payload_b64;
    unsigned char hmac_out[EVP_MAX_MD_SIZE] = {0};
    unsigned int  hmac_len = 0;
    HMAC(EVP_sha256(),
         secret.c_str(), static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char *>(signing_input.c_str()),
         signing_input.size(),
         hmac_out, &hmac_len);

    std::string sig_raw;
    if (!kislay_gateway_base64url_decode(sig_b64, sig_raw)) return false;
    if (sig_raw.size() != hmac_len) return false;

    // Constant-time comparison
    int diff = 0;
    for (unsigned int i = 0; i < hmac_len; ++i) {
        diff |= (static_cast<unsigned char>(sig_raw[i]) ^ hmac_out[i]);
    }
    if (diff != 0) return false;

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────

// Generate cryptographically random hex string of given byte length (gateway)
static std::string kislay_gw_random_hex(size_t bytes) {
    std::string result(bytes * 2, '0');
    unsigned char buf[32] = {0};
#ifdef __APPLE__
    arc4random_buf(buf, bytes);
#elif defined(_WIN32)
    BCryptGenRandom(NULL, buf, (ULONG)bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(buf, 1, bytes, f); fclose(f); }
#endif
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < bytes; i++) {
        result[i*2]   = hex[buf[i] >> 4];
        result[i*2+1] = hex[buf[i] & 0xf];
    }
    return result;
}

static bool kislayphp_gateway_is_idempotent_method(const std::string &method) {
    return method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "PUT" || method == "DELETE";
}

static bool kislayphp_gateway_circuit_allow_request(php_kislayphp_gateway_t *gateway,
                                                    const std::string &upstream_key,
                                                    std::time_t now,
                                                    std::string *deny_reason = nullptr) {
    std::lock_guard<std::mutex> guard(gateway->lock);
    auto &state = gateway->circuit_states[upstream_key];
    if (state.open_until > now) {
        if (deny_reason != nullptr) {
            *deny_reason = "Circuit breaker open";
        }
        return false;
    }

    if (state.open_until != 0 && state.open_until <= now) {
        if (state.half_open_in_flight) {
            if (deny_reason != nullptr) {
                *deny_reason = "Circuit breaker half-open";
            }
            return false;
        }
        state.half_open_in_flight = true;
    }

    return true;
}

static void kislayphp_gateway_circuit_record_result(php_kislayphp_gateway_t *gateway,
                                                    const std::string &upstream_key,
                                                    std::time_t now,
                                                    bool failed) {
    std::lock_guard<std::mutex> guard(gateway->lock);
    auto &state = gateway->circuit_states[upstream_key];
    if (failed) {
        if (state.half_open_in_flight || (state.failures + 1) >= gateway->circuit_failure_threshold) {
            state.open_until = now + gateway->circuit_open_seconds;
            state.failures = 0;
            state.half_open_in_flight = false;
            return;
        }
        state.failures++;
        return;
    }

    state.failures = 0;
    state.open_until = 0;
    state.half_open_in_flight = false;
}

static bool kislayphp_proxy_request(struct mg_connection *conn,
                                    const struct mg_request_info *info,
                                    const kislayphp_gateway_route &route,
                                    size_t max_body_bytes,
                                    zend_long read_timeout_ms,
                                    int *status_code_out,
                                    const std::vector<std::pair<std::string,std::string>> &extra_headers = {},
                                    bool write_error_response = true) {
    if (status_code_out != nullptr) {
        *status_code_out = 0;
    }
    if (max_body_bytes > 0 && info->content_length > static_cast<long long>(max_body_bytes)) {
        if (write_error_response) {
            kislayphp_send_error(conn, 413, "Payload Too Large");
        }
        if (status_code_out != nullptr) {
            *status_code_out = 413;
        }
        return false;
    }
    std::string path = info->local_uri ? info->local_uri : (info->request_uri ? info->request_uri : "/");
    std::string target_path = kislayphp_join_paths(route.base_path, path);
    if (info->query_string && *info->query_string) {
        target_path.append("?");
        target_path.append(info->query_string);
    }

    std::string method = info->request_method ? info->request_method : "GET";
    std::string forwarded_for = kislayphp_request_forwarded_for(info);
    std::string forwarded_proto = kislayphp_request_forwarded_proto(info);
    std::string forwarded_host = kislayphp_request_forwarded_host(info);
    std::string upstream_key = kislayphp_upstream_key(route);

    auto &pool = kislayphp_gateway_upstream_pool();

    for (int connect_attempt = 0; connect_attempt < 2; ++connect_attempt) {
        char error_buf[256] = {0};
        struct mg_connection *target = pool.take(upstream_key);
        bool from_pool = target != nullptr;
        bool pooled_retry_allowed = from_pool && kislayphp_gateway_is_idempotent_method(method);
        if (target == nullptr) {
            target = mg_connect_client(route.host.c_str(), route.port, route.use_tls ? 1 : 0, error_buf, sizeof(error_buf));
        }
        if (target == nullptr) {
            php_error_docref(nullptr, E_WARNING, "Upstream connect failed for %s://%s:%d (%s)",
                             route.use_tls ? "https" : "http",
                             route.host.c_str(),
                             route.port,
                             error_buf[0] != '\0' ? error_buf : "unknown error");
            if (write_error_response) {
                kislayphp_send_error(conn, 502, "Upstream connect failed");
            }
            if (status_code_out != nullptr) {
                *status_code_out = 502;
            }
            return false;
        }

        if (mg_printf(target, "%s %s HTTP/1.1\r\n", method.c_str(), target_path.c_str()) <= 0 ||
            mg_printf(target, "Host: %s:%d\r\n", route.host.c_str(), route.port) <= 0 ||
            mg_printf(target, "Connection: keep-alive\r\n") <= 0 ||
            mg_printf(target, "X-Forwarded-For: %s\r\n", forwarded_for.c_str()) <= 0 ||
            mg_printf(target, "X-Forwarded-Proto: %s\r\n", forwarded_proto.c_str()) <= 0 ||
            mg_printf(target, "X-Forwarded-Host: %s\r\n", forwarded_host.c_str()) <= 0) {
            mg_close_connection(target);
            if (pooled_retry_allowed) {
                continue;
            }
            if (write_error_response) {
                kislayphp_send_error(conn, 502, "Upstream request write failed");
            }
            if (status_code_out != nullptr) {
                *status_code_out = 502;
            }
            return false;
        }

        for (const auto &h : extra_headers) {
            if (mg_printf(target, "%s: %s\r\n", h.first.c_str(), h.second.c_str()) <= 0) {
                mg_close_connection(target);
                if (pooled_retry_allowed) {
                    continue;
                }
                if (write_error_response) {
                    kislayphp_send_error(conn, 502, "Upstream request write failed");
                }
                if (status_code_out != nullptr) {
                    *status_code_out = 502;
                }
                return false;
            }
        }

        bool has_content_length = false;
        bool request_write_failed = false;
        for (int i = 0; i < info->num_headers; ++i) {
            const char *name = info->http_headers[i].name;
            const char *value = info->http_headers[i].value;
            if (name == nullptr || value == nullptr) {
                continue;
            }
            if (::strcasecmp(name, "Host") == 0 ||
                ::strcasecmp(name, "X-Forwarded-For") == 0 ||
                ::strcasecmp(name, "X-Forwarded-Proto") == 0 ||
                ::strcasecmp(name, "X-Forwarded-Host") == 0 ||
                kislayphp_is_hop_header(name)) {
                continue;
            }
            if (::strcasecmp(name, "Content-Length") == 0) {
                has_content_length = true;
            }
            if (mg_printf(target, "%s: %s\r\n", name, value) <= 0) {
                request_write_failed = true;
                break;
            }
        }

        if (!request_write_failed && !has_content_length && info->content_length >= 0) {
            if (mg_printf(target, "Content-Length: %lld\r\n", static_cast<long long>(info->content_length)) <= 0) {
                request_write_failed = true;
            }
        }
        if (!request_write_failed && mg_printf(target, "\r\n") <= 0) {
            request_write_failed = true;
        }
        if (request_write_failed) {
            mg_close_connection(target);
            if (pooled_retry_allowed) {
                continue;
            }
            if (write_error_response) {
                kislayphp_send_error(conn, 502, "Upstream request write failed");
            }
            if (status_code_out != nullptr) {
                *status_code_out = 502;
            }
            return false;
        }

        if (info->content_length > 0) {
            char buffer[8192];
            long long remaining = info->content_length;
            while (remaining > 0) {
                int to_read = remaining > static_cast<long long>(sizeof(buffer))
                    ? static_cast<int>(sizeof(buffer))
                    : static_cast<int>(remaining);
                int read_now = mg_read(conn, buffer, to_read);
                if (read_now <= 0 || mg_write(target, buffer, static_cast<size_t>(read_now)) != read_now) {
                    request_write_failed = true;
                    break;
                }
                remaining -= read_now;
            }
        }

        if (request_write_failed) {
            mg_close_connection(target);
            if (pooled_retry_allowed) {
                continue;
            }
            if (write_error_response) {
                kislayphp_send_error(conn, 502, "Upstream request body failed");
            }
            if (status_code_out != nullptr) {
                *status_code_out = 502;
            }
            return false;
        }

        int response_timeout = static_cast<int>(read_timeout_ms > 0 ? read_timeout_ms : 10000);
        if (mg_get_response(target, error_buf, sizeof(error_buf), response_timeout) < 0) {
            mg_close_connection(target);
            if (pooled_retry_allowed) {
                continue;
            }
            if (write_error_response) {
                kislayphp_send_error(conn, 502, "Upstream response failed");
            }
            if (status_code_out != nullptr) {
                *status_code_out = 502;
            }
            return false;
        }

        const struct mg_response_info *resp_info = mg_get_response_info(target);
        int status_code = resp_info ? resp_info->status_code : 502;
        if (status_code_out != nullptr) {
            *status_code_out = status_code;
        }
        const char *status_text = (resp_info && resp_info->status_text) ? resp_info->status_text : "Bad Gateway";
        mg_printf(conn, "HTTP/1.1 %d %s\r\n", status_code, status_text);

        bool resp_has_length = false;
        bool resp_has_request_id = false;
        if (resp_info) {
            for (int i = 0; i < resp_info->num_headers; ++i) {
                const char *name = resp_info->http_headers[i].name;
                const char *value = resp_info->http_headers[i].value;
                if (name == nullptr || value == nullptr) {
                    continue;
                }
                if (kislayphp_is_hop_header(name)) {
                    continue;
                }
                if (::strcasecmp(name, "Content-Length") == 0) {
                    resp_has_length = true;
                }
                if (::strcasecmp(name, "X-Request-ID") == 0) {
                    resp_has_request_id = true;
                }
                mg_printf(conn, "%s: %s\r\n", name, value);
            }
            if (!resp_has_length && resp_info->content_length >= 0) {
                mg_printf(conn, "Content-Length: %lld\r\n", resp_info->content_length);
            }
        }
        if (!resp_has_request_id) {
            for (const auto &header : extra_headers) {
                if (::strcasecmp(header.first.c_str(), "X-Request-ID") == 0) {
                    mg_printf(conn, "X-Request-ID: %s\r\n", header.second.c_str());
                    break;
                }
            }
        }
        mg_printf(conn, "Connection: close\r\n\r\n");

        char buffer[8192];
        int read_len = 0;
        while ((read_len = mg_read(target, buffer, sizeof(buffer))) > 0) {
            mg_write(conn, buffer, static_cast<size_t>(read_len));
        }

        if (read_len < 0) {
            mg_close_connection(target);
            return false;
        }

        if (kislayphp_can_reuse_upstream_response(resp_info)) {
            pool.put(upstream_key, target);
        } else {
            mg_close_connection(target);
        }
        return true;
    }

    if (write_error_response) {
        kislayphp_send_error(conn, 502, "Upstream response failed");
    }
    if (status_code_out != nullptr) {
        *status_code_out = 502;
    }
    return false;
}

static bool kislayphp_gateway_proxy_with_resilience(struct mg_connection *conn,
                                                    const struct mg_request_info *info,
                                                    const kislayphp_gateway_route &route,
                                                    const php_kislayphp_gateway_t *gateway,
                                                    const std::vector<std::pair<std::string,std::string>> &extra_headers,
                                                    int *status_code_out) {
    std::string method = info->request_method ? kislayphp_to_upper(info->request_method) : "GET";
    zend_long retries = kislayphp_gateway_is_idempotent_method(method) ? gateway->proxy_retries : 0;
    if (retries < 0) {
        retries = 0;
    }

    for (zend_long attempt = 0; attempt <= retries; ++attempt) {
        bool final_attempt = attempt == retries;
        int attempt_status = 0;
        bool ok = kislayphp_proxy_request(conn,
                                          info,
                                          route,
                                          gateway->max_body_bytes,
                                          gateway->proxy_read_timeout_ms,
                                          &attempt_status,
                                          extra_headers,
                                          final_attempt);
        if (status_code_out != nullptr) {
            *status_code_out = attempt_status;
        }
        if (ok) {
            return true;
        }
        if (attempt_status != 502 || final_attempt) {
            return false;
        }
    }

    return false;
}

static int kislayphp_gateway_begin_request(struct mg_connection *conn) {
    const struct mg_request_info *info = mg_get_request_info(conn);
    if (info == nullptr || info->user_data == nullptr) {
        return 0;
    }

    auto *gateway = static_cast<php_kislayphp_gateway_t *>(info->user_data);
    std::string method = info->request_method ? info->request_method : "";
    method = kislayphp_to_upper(method);
    std::string path = info->local_uri ? info->local_uri : (info->request_uri ? info->request_uri : "");

    // Auth check stays at the edge, but auth state itself belongs to Core.
    // Gateway validates presence/signature when configured and forwards the original
    // Authorization header downstream without synthesizing identity headers.
    std::vector<std::pair<std::string,std::string>> extra_proxy_headers;

    if (gateway->auth_required) {
        if (!kislay_gateway_path_excluded(path, gateway->auth_exclude_prefixes)) {
            const char *auth_hdr = kislayphp_get_header(info, "Authorization");

            if (!gateway->jwt_secret.empty()) {
                bool valid = false;
                if (auth_hdr != nullptr && std::strncmp(auth_hdr, "Bearer ", 7) == 0) {
                    std::string token(auth_hdr + 7);
                    valid = kislay_gateway_validate_jwt(token, gateway->jwt_secret);
                }
                if (!valid) {
                    static const char jwt_err[] = "{\"error\":\"Unauthorized\"}";
                    mg_printf(conn,
                              "HTTP/1.1 401 Unauthorized\r\n"
                              "Content-Type: application/json; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: close\r\n\r\n"
                              "%s",
                              sizeof(jwt_err) - 1, jwt_err);
                    return 1;
                }
            } else {
                // Legacy simple bearer token mode
                if (gateway->auth_bearer_token.empty()) {
                    kislayphp_send_error(conn, 503, "Gateway auth token not configured");
                    return 1;
                }
                if (auth_hdr == nullptr || *auth_hdr == '\0') {
                    kislayphp_send_error(conn, 401, "Missing Authorization header");
                    return 1;
                }
                std::string expected = "Bearer ";
                expected.append(gateway->auth_bearer_token);
                if (std::string(auth_hdr) != expected) {
                    kislayphp_send_error(conn, 401, "Invalid Authorization token");
                    return 1;
                }
            }
        }
    }

    if (gateway->rate_limit_enabled) {
        std::time_t now = std::time(nullptr);
        std::string key = kislayphp_client_identifier(info);
        key.push_back('|');
        key.append(method);
        std::lock_guard<std::mutex> guard(gateway->lock);
        auto &entry = gateway->rate_limits[key];
        if (entry.window_start == 0 || (now - entry.window_start) >= gateway->rate_limit_window_seconds) {
            entry.window_start = now;
            entry.count = 0;
        }
        if (entry.count >= gateway->rate_limit_requests) {
            kislayphp_send_error(conn, 429, "Rate limit exceeded");
            return 1;
        }
        entry.count++;
    }

    // Preserve the request identifier end-to-end. Core will continue using the same
    // value and emit it back if present.
    {
        const char *request_id_hdr = kislayphp_get_header(info, "X-Request-ID");
        if (request_id_hdr == nullptr || *request_id_hdr == '\0') {
            extra_proxy_headers.emplace_back("X-Request-ID", kislay_gw_random_hex(16));
        }
    }

    kislayphp_gateway_route match;
    bool found = false;
    zval resolver;
    ZVAL_UNDEF(&resolver);
    bool has_resolver = false;
    {
        std::lock_guard<std::mutex> guard(gateway->lock);
        for (const auto &route : gateway->routes) {
            if (route.method == method && kislayphp_path_matches(route.path, path)) {
                match = route;
                found = true;
                break;
            }
        }
        if (!found && gateway->has_fallback) {
            match = gateway->fallback_route;
            found = true;
        }
        if (gateway->has_resolver) {
            ZVAL_COPY(&resolver, &gateway->resolver);
            has_resolver = true;
        }
    }

    if (!found) {
        kislayphp_send_error(conn, 404, "Not Found");
        return 1;
    }

    if (match.use_service) {
        std::string rpc_target;
        bool rpc_ok = false;
#ifdef KISLAYPHP_RPC
        if (!has_resolver && kislayphp_rpc_enabled()) {
            std::string error;
            rpc_ok = kislayphp_rpc_resolve_service(match.service, &rpc_target, &error);
        }
#endif

        if (!has_resolver && !rpc_ok) {
            kislayphp_send_error(conn, 502, "Service resolver not configured");
            return 1;
        }
        zval args[3];
        ZVAL_STRING(&args[0], match.service.c_str());
        ZVAL_STRING(&args[1], method.c_str());
        ZVAL_STRING(&args[2], path.c_str());
        zval retval;
        bool ok = false;
        if (has_resolver) {
            std::string resolver_error;
            ok = kislayphp_call_php(&resolver, 3, args, &retval, &resolver_error);
            if ((!ok || EG(exception) != nullptr) && !resolver_error.empty()) {
                php_error_docref(nullptr, E_WARNING, "Gateway resolver failure: %s", resolver_error.c_str());
            }
        }
        zval_ptr_dtor(&args[0]);
        zval_ptr_dtor(&args[1]);
        zval_ptr_dtor(&args[2]);
        if (has_resolver) {
            zval_ptr_dtor(&resolver);
        }
        std::string target;
        if (has_resolver) {
            if (!ok || EG(exception) != nullptr || Z_TYPE(retval) != IS_STRING) {
                if (ok) {
                    zval_ptr_dtor(&retval);
                }
                kislayphp_send_error(conn, 502, "Service resolver failed");
                return 1;
            }
            target.assign(Z_STRVAL(retval), Z_STRLEN(retval));
            zval_ptr_dtor(&retval);
        } else if (rpc_ok) {
            target = rpc_target;
        } else {
            kislayphp_send_error(conn, 502, "Service resolver failed");
            return 1;
        }

        kislayphp_gateway_route resolved = match;
        resolved.target = target;
        resolved.use_service = false;
        if (!kislayphp_parse_target(resolved.target, resolved)) {
            kislayphp_send_error(conn, 502, "Invalid upstream target");
            return 1;
        }
        if (gateway->circuit_breaker_enabled) {
            std::time_t now = std::time(nullptr);
            std::string upstream_key = resolved.host + ":" + std::to_string(resolved.port);
            std::string deny_reason;
            if (!kislayphp_gateway_circuit_allow_request(gateway, upstream_key, now, &deny_reason)) {
                kislayphp_send_error(conn, 503, deny_reason.c_str());
                return 1;
            }

            int upstream_status = 0;
            bool ok_proxy = kislayphp_gateway_proxy_with_resilience(conn, info, resolved, gateway, extra_proxy_headers, &upstream_status);
            bool failed = !ok_proxy || upstream_status >= 500;
            kislayphp_gateway_circuit_record_result(gateway, upstream_key, now, failed);
            return 1;
        }

        kislayphp_gateway_proxy_with_resilience(conn, info, resolved, gateway, extra_proxy_headers, nullptr);
        return 1;
    }

    if (has_resolver) {
        zval_ptr_dtor(&resolver);
    }

    if (gateway->circuit_breaker_enabled) {
        std::time_t now = std::time(nullptr);
        std::string upstream_key = match.host + ":" + std::to_string(match.port);
        std::string deny_reason;
        if (!kislayphp_gateway_circuit_allow_request(gateway, upstream_key, now, &deny_reason)) {
            kislayphp_send_error(conn, 503, deny_reason.c_str());
            return 1;
        }

        int upstream_status = 0;
        bool ok_proxy = kislayphp_gateway_proxy_with_resilience(conn, info, match, gateway, extra_proxy_headers, &upstream_status);
        bool failed = !ok_proxy || upstream_status >= 500;
        kislayphp_gateway_circuit_record_result(gateway, upstream_key, now, failed);
        return 1;
    }

    kislayphp_gateway_proxy_with_resilience(conn, info, match, gateway, extra_proxy_headers, nullptr);
    return 1;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_add, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, method, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, target, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_add_service, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, method, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, service, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_listen, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_set_threads, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, count, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_set_resolver, 0, 0, 1)
    ZEND_ARG_CALLABLE_INFO(0, resolver, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_set_fallback, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, target, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_set_fallback_service, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, service, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_kislayphp_gateway_require_auth, 0, 1, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, secret, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_kislayphp_gateway_set_auth_exclude, 0, 1, IS_VOID, 0)
    ZEND_ARG_TYPE_INFO(0, paths, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(KislayPHPGateway, __construct) {
    ZEND_PARSE_PARAMETERS_NONE();
}

PHP_METHOD(KislayPHPGateway, addRoute) {
    char *method = nullptr;
    size_t method_len = 0;
    char *path = nullptr;
    size_t path_len = 0;
    char *target = nullptr;
    size_t target_len = 0;
    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(method, method_len)
        Z_PARAM_STRING(path, path_len)
        Z_PARAM_STRING(target, target_len)
    ZEND_PARSE_PARAMETERS_END();

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    kislayphp_gateway_route route;
    route.method.assign(kislayphp_to_upper(std::string(method, method_len)));
    route.path.assign(path, path_len);
    route.target.assign(target, target_len);
    route.use_service = false;
    route.use_tls = false;
    if (!kislayphp_parse_target(route.target, route)) {
        zend_throw_exception(zend_ce_exception, "Invalid target (expected http(s)://host[:port][/base])", 0);
        RETURN_FALSE;
    }
    if (route.path.empty()) {
        route.path = "/";
    }

    std::lock_guard<std::mutex> guard(obj->lock);
    obj->routes.push_back(route);
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, addServiceRoute) {
    char *method = nullptr;
    size_t method_len = 0;
    char *path = nullptr;
    size_t path_len = 0;
    char *service = nullptr;
    size_t service_len = 0;
    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(method, method_len)
        Z_PARAM_STRING(path, path_len)
        Z_PARAM_STRING(service, service_len)
    ZEND_PARSE_PARAMETERS_END();

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    kislayphp_gateway_route route;
    route.method.assign(kislayphp_to_upper(std::string(method, method_len)));
    route.path.assign(path, path_len);
    route.target.clear();
    route.service.assign(service, service_len);
    route.use_service = true;
    route.use_tls = false;
    if (route.path.empty()) {
        route.path = "/";
    }

    std::lock_guard<std::mutex> guard(obj->lock);
    obj->routes.push_back(route);
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, routes) {
    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    array_init(return_value);
    std::lock_guard<std::mutex> guard(obj->lock);
    for (const auto &route : obj->routes) {
        zval entry;
        array_init(&entry);
        add_assoc_string(&entry, "method", route.method.c_str());
        add_assoc_string(&entry, "path", route.path.c_str());
        if (route.use_service) {
            add_assoc_string(&entry, "service", route.service.c_str());
        } else {
            add_assoc_string(&entry, "target", route.target.c_str());
        }
        add_next_index_zval(return_value, &entry);
    }
}

PHP_METHOD(KislayPHPGateway, setThreads) {
    zend_long count = 1;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(count)
    ZEND_PARSE_PARAMETERS_END();

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    if (obj->ctx != nullptr) {
        zend_throw_exception(zend_ce_exception, "Gateway already running", 0);
        RETURN_FALSE;
    }

    obj->thread_count = kislayphp_sanitize_thread_count(static_cast<int>(count), "Kislay\\Gateway\\Gateway::setThreads");
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, setResolver) {
    zval *resolver = nullptr;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ZVAL(resolver)
    ZEND_PARSE_PARAMETERS_END();

    if (!zend_is_callable(resolver, 0, nullptr)) {
        zend_throw_exception(zend_ce_exception, "Resolver must be callable", 0);
        RETURN_FALSE;
    }

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    std::lock_guard<std::mutex> guard(obj->lock);
    if (obj->has_resolver) {
        zval_ptr_dtor(&obj->resolver);
        obj->has_resolver = false;
    }
    ZVAL_COPY(&obj->resolver, resolver);
    obj->has_resolver = true;
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, listen) {
    char *host = nullptr;
    size_t host_len = 0;
    zend_long port = 0;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(host, host_len)
        Z_PARAM_LONG(port)
    ZEND_PARSE_PARAMETERS_END();

    if (port <= 0 || port > 65535) {
        zend_throw_exception(zend_ce_exception, "Invalid port", 0);
        RETURN_FALSE;
    }

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    if (obj->ctx != nullptr) {
        zend_throw_exception(zend_ce_exception, "Gateway already running", 0);
        RETURN_FALSE;
    }
    kislayphp_disable_stack_guard_for_nts("Kislay\\Gateway\\Gateway::listen");
    obj->thread_count = kislayphp_sanitize_thread_count(obj->thread_count, "Kislay\\Gateway\\Gateway::listen");
#if defined(ZTS)
    {
        std::lock_guard<std::mutex> guard(obj->lock);
        if (obj->has_resolver) {
            zend_throw_exception(zend_ce_exception,
                                 "PHP resolvers are not supported on ZTS builds; use RPC discovery or direct targets",
                                 0);
            RETURN_FALSE;
        }
    }
#endif

    std::string listen_addr = std::string(host, host_len) + ":" + std::to_string(port);
    std::vector<const char *> options;
    options.push_back("listening_ports");
    options.push_back(listen_addr.c_str());
    std::string threads_value = std::to_string(obj->thread_count);
    options.push_back("num_threads");
    options.push_back(threads_value.c_str());
    options.push_back(nullptr);

    struct mg_callbacks callbacks;
    std::memset(&callbacks, 0, sizeof(callbacks));
    callbacks.begin_request = kislayphp_gateway_begin_request;

    obj->ctx = mg_start(&callbacks, obj, options.data());
    if (obj->ctx == nullptr) {
        zend_throw_exception(zend_ce_exception, "Failed to start gateway", 0);
        RETURN_FALSE;
    }

    obj->running = true;
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, setFallbackTarget) {
    char *target = nullptr;
    size_t target_len = 0;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(target, target_len)
    ZEND_PARSE_PARAMETERS_END();

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    kislayphp_gateway_route route;
    route.method = "*";
    route.path = "*";
    route.target.assign(target, target_len);
    route.use_service = false;
    route.use_tls = false;
    if (!kislayphp_parse_target(route.target, route)) {
        zend_throw_exception(zend_ce_exception, "Invalid fallback target (expected http(s)://host[:port][/base])", 0);
        RETURN_FALSE;
    }

    std::lock_guard<std::mutex> guard(obj->lock);
    obj->fallback_route = route;
    obj->has_fallback = true;
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, setFallbackService) {
    char *service = nullptr;
    size_t service_len = 0;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(service, service_len)
    ZEND_PARSE_PARAMETERS_END();

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    kislayphp_gateway_route route;
    route.method = "*";
    route.path = "*";
    route.target.clear();
    route.service.assign(service, service_len);
    route.use_service = true;
    route.use_tls = false;

    std::lock_guard<std::mutex> guard(obj->lock);
    obj->fallback_route = route;
    obj->has_fallback = true;
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, stop) {
    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    obj->running = false;
    if (obj->ctx != nullptr) {
        mg_stop(obj->ctx);
        obj->ctx = nullptr;
    }
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, requireAuth) {
    char *secret = nullptr;
    size_t secret_len = 0;
    zval *options = nullptr;
    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(secret, secret_len)
        Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY(options)
    ZEND_PARSE_PARAMETERS_END();

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    std::lock_guard<std::mutex> guard(obj->lock);

    obj->jwt_secret.assign(secret, secret_len);
    obj->auth_required = true;

    if (options != nullptr && Z_TYPE_P(options) == IS_ARRAY) {
        // 'exclude' => ['/health', '/public']
        zval *exclude_val = zend_hash_str_find(Z_ARRVAL_P(options), "exclude", sizeof("exclude") - 1);
        if (exclude_val != nullptr && Z_TYPE_P(exclude_val) == IS_ARRAY) {
            obj->auth_exclude_prefixes.clear();
            zval *item;
            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(exclude_val), item) {
                if (Z_TYPE_P(item) == IS_STRING) {
                    obj->auth_exclude_prefixes.emplace_back(Z_STRVAL_P(item), Z_STRLEN_P(item));
                }
            } ZEND_HASH_FOREACH_END();
        }

        // 'header' => 'X-Internal-Token'
        zval *header_val = zend_hash_str_find(Z_ARRVAL_P(options), "header", sizeof("header") - 1);
        if (header_val != nullptr && Z_TYPE_P(header_val) == IS_STRING) {
            obj->auth_user_header.assign(Z_STRVAL_P(header_val), Z_STRLEN_P(header_val));
        }
    }
}

PHP_METHOD(KislayPHPGateway, setAuthExclude) {
    zval *paths = nullptr;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(paths)
    ZEND_PARSE_PARAMETERS_END();

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    std::lock_guard<std::mutex> guard(obj->lock);

    zval *item;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(paths), item) {
        if (Z_TYPE_P(item) == IS_STRING) {
            obj->auth_exclude_prefixes.emplace_back(Z_STRVAL_P(item), Z_STRLEN_P(item));
        }
    } ZEND_HASH_FOREACH_END();
}

static const zend_function_entry kislayphp_gateway_methods[] = {
    PHP_ME(KislayPHPGateway, __construct, arginfo_kislayphp_gateway_void, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, addRoute, arginfo_kislayphp_gateway_add, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, addServiceRoute, arginfo_kislayphp_gateway_add_service, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, routes, arginfo_kislayphp_gateway_void, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, setThreads, arginfo_kislayphp_gateway_set_threads, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, setResolver, arginfo_kislayphp_gateway_set_resolver, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, setFallbackTarget, arginfo_kislayphp_gateway_set_fallback, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, setFallbackService, arginfo_kislayphp_gateway_set_fallback_service, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, listen, arginfo_kislayphp_gateway_listen, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, stop, arginfo_kislayphp_gateway_void, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, requireAuth, arginfo_kislayphp_gateway_require_auth, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, setAuthExclude, arginfo_kislayphp_gateway_set_auth_exclude, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

PHP_MINIT_FUNCTION(kislayphp_gateway) {
    if (mg_init_library(MG_FEATURES_DEFAULT | MG_FEATURES_TLS) == 0) {
        php_error_docref(nullptr, E_WARNING, "Failed to initialize civetweb TLS library features");
    }
    zend_class_entry ce;
    INIT_NS_CLASS_ENTRY(ce, "Kislay\\Gateway", "Gateway", kislayphp_gateway_methods);
    kislayphp_gateway_ce = zend_register_internal_class(&ce);
    zend_register_class_alias("KislayPHP\\Gateway\\Gateway", kislayphp_gateway_ce);
    kislayphp_gateway_ce->create_object = kislayphp_gateway_create_object;
    std::memcpy(&kislayphp_gateway_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    kislayphp_gateway_handlers.offset = XtOffsetOf(php_kislayphp_gateway_t, std);
    kislayphp_gateway_handlers.free_obj = kislayphp_gateway_free_obj;
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(kislayphp_gateway) {
    mg_exit_library();
    return SUCCESS;
}

PHP_MINFO_FUNCTION(kislayphp_gateway) {
    php_info_print_table_start();
    php_info_print_table_header(2, "kislayphp_gateway support", "enabled");
    php_info_print_table_row(2, "Version", PHP_KISLAYPHP_GATEWAY_VERSION);
    php_info_print_table_end();
}

zend_module_entry kislayphp_gateway_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_KISLAYPHP_GATEWAY_EXTNAME,
    nullptr,
    PHP_MINIT(kislayphp_gateway),
    PHP_MSHUTDOWN(kislayphp_gateway),
    nullptr,
    nullptr,
    PHP_MINFO(kislayphp_gateway),
    PHP_KISLAYPHP_GATEWAY_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif

extern "C" {
ZEND_DLEXPORT zend_module_entry *get_module(void) {
    return &kislayphp_gateway_module_entry;
}
}
