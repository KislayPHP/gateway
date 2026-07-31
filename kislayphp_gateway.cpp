extern "C" {
#include "php.h"
#include "ext/standard/info.h"
#include "Zend/zend_exceptions.h"
}

#include "php_kislayphp_gateway.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <atomic>
#include <chrono>
#include <civetweb.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <array>
#include <mutex>
#include <shared_mutex>
#include <strings.h>
#include <string>
#include <unordered_map>
#include <vector>
#ifdef __linux__
#include <sys/random.h>
#endif

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
    std::string upstream_key;  // pre-computed "host:port" to avoid per-request alloc
    std::string pool_key;      // pre-computed "host:port" or "host:ports" for TLS
};

struct kislayphp_rate_limit_entry {
    int64_t window_start_ms;  // milliseconds from steady_clock epoch
    zend_long count;
};

// Per-host circuit breaker state. Failures and open_until_ms are atomics so the
// hot-path check and update need no global lock — only the map insertion (first-seen
// host) takes an exclusive lock on circuit_map_rwlock.
struct PerHostCircuitState {
    std::atomic<zend_long> failures{0};
    std::atomic<int64_t>   open_until_ms{0};
};

// 64-bit FNV-1a hash — fast, no heap allocation, feeds directly from two string_views.
// Used to turn "client_id + method" into a single uint64_t map key, avoiding the
// per-request string construction that std::hash<string> would require.
static inline uint64_t kislayphp_rl_hash(const char *ip, size_t ip_len,
                                          const char *method, size_t method_len) noexcept {
    constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
    constexpr uint64_t FNV_PRIME  = 1099511628211ULL;
    uint64_t h = FNV_OFFSET;
    for (size_t i = 0; i < ip_len;     ++i) { h ^= static_cast<uint8_t>(ip[i]);     h *= FNV_PRIME; }
    h ^= static_cast<uint8_t>('|'); h *= FNV_PRIME;
    for (size_t i = 0; i < method_len; ++i) { h ^= static_cast<uint8_t>(method[i]); h *= FNV_PRIME; }
    return h;
}

// 64-shard rate-limit table. Each shard has its own mutex so concurrent requests
// from different IPs (hashing to different shards) never contend.
// Keys are uint64_t FNV-1a hashes of (client_ip + method) — no heap allocation per request.
static constexpr size_t RATE_LIMIT_SHARDS = 64;
struct RateLimitShard {
    alignas(64) std::mutex lock;
    std::unordered_map<uint64_t, kislayphp_rate_limit_entry> entries;
};

struct kislayphp_native_service_entry {
    std::vector<kislayphp_gateway_route> targets;
    std::atomic<uint32_t> next_index{0};
};

using kislayphp_native_service_registry =
    std::unordered_map<std::string, std::shared_ptr<kislayphp_native_service_entry>>;

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
    std::shared_ptr<kislayphp_native_service_registry> native_services;
    bool auth_required;
    std::string auth_bearer_token;
    std::vector<std::string> auth_exclude_prefixes;
    std::string jwt_secret;
    std::string auth_user_header;
    bool trace_enabled;
    bool rate_limit_enabled;
    zend_long rate_limit_requests;
    zend_long rate_limit_window_seconds;
    std::array<RateLimitShard, RATE_LIMIT_SHARDS> rate_limit_shards;
    std::atomic<uint64_t> rate_limit_request_counter{0};
    bool circuit_breaker_enabled;
    zend_long circuit_failure_threshold;
    zend_long circuit_open_seconds;
    std::unordered_map<std::string, std::shared_ptr<PerHostCircuitState>> circuit_states;
    std::shared_mutex circuit_map_lock;
    // Frozen route table: built once at listen() time for lock-free O(1) hot-path lookup.
    // frozen_exact: (method + '\0' + path) → route for exact paths.
    // frozen_prefix: wildcard routes (path ends in '*'), sorted longest prefix first.
    std::atomic<bool> route_table_frozen;
    std::unordered_map<std::string, kislayphp_gateway_route> frozen_exact;
    std::vector<kislayphp_gateway_route> frozen_prefix;
    zend_object std;
} php_kislayphp_gateway_t;

static zend_object_handlers kislayphp_gateway_handlers;

static zend_long kislayphp_env_long(const char *name, zend_long fallback) {
    const char *value = std::getenv(name);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }
    return static_cast<zend_long>(std::strtoll(value, nullptr, 10));
}

static bool kislayphp_is_hop_header(const char *name) {
    if (name == nullptr || name[0] == '\0') return false;
    // Dispatch on lowercased first char — most non-hop headers fail here with
    // zero strcasecmp calls instead of up to seven.
    switch (name[0] | 0x20) {
    case 'c': return ::strcasecmp(name, "Connection") == 0;
    case 'p': return ::strcasecmp(name, "Proxy-Connection") == 0;
    case 'k': return ::strcasecmp(name, "Keep-Alive") == 0;
    case 't': return ::strcasecmp(name, "TE") == 0 ||
                     ::strcasecmp(name, "Trailer") == 0 ||
                     ::strcasecmp(name, "Transfer-Encoding") == 0;
    case 'u': return ::strcasecmp(name, "Upgrade") == 0;
    default:  return false;
    }
}

// True for headers that must be stripped before forwarding upstream:
// Host, X-Forwarded-*, plus all hop-by-hop headers.  Single switch on the
// lowercased first character keeps the hot path to at most one strcasecmp.
static bool kislayphp_skip_upstream_header(const char *name) {
    if (name == nullptr || name[0] == '\0') return false;
    switch (name[0] | 0x20) {
    case 'h': return ::strcasecmp(name, "Host") == 0;
    case 'x': return ::strncasecmp(name, "X-Forwarded-", 12) == 0;
    case 'c': return ::strcasecmp(name, "Connection") == 0;
    case 'p': return ::strcasecmp(name, "Proxy-Connection") == 0;
    case 'k': return ::strcasecmp(name, "Keep-Alive") == 0;
    case 't': return ::strcasecmp(name, "TE") == 0 ||
                     ::strcasecmp(name, "Trailer") == 0 ||
                     ::strcasecmp(name, "Transfer-Encoding") == 0;
    case 'u': return ::strcasecmp(name, "Upgrade") == 0;
    default:  return false;
    }
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

static bool kislayphp_request_wants_close(const struct mg_request_info *info) {
    const char *connection = kislayphp_get_header(info, "Connection");
    return connection != nullptr && ::strcasecmp(connection, "close") == 0;
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
    new (&obj->native_services) std::shared_ptr<kislayphp_native_service_registry>();
    new (&obj->auth_bearer_token) std::string();
    new (&obj->auth_exclude_prefixes) std::vector<std::string>();
    new (&obj->jwt_secret) std::string();
    new (&obj->auth_user_header) std::string();
    new (&obj->rate_limit_shards) std::array<RateLimitShard, RATE_LIMIT_SHARDS>();
    new (&obj->circuit_states) std::unordered_map<std::string, std::shared_ptr<PerHostCircuitState>>();
    new (&obj->circuit_map_lock) std::shared_mutex();
    new (&obj->route_table_frozen) std::atomic<bool>(false);
    new (&obj->frozen_exact) std::unordered_map<std::string, kislayphp_gateway_route>();
    new (&obj->frozen_prefix) std::vector<kislayphp_gateway_route>();
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
    obj->native_services = std::make_shared<kislayphp_native_service_registry>();
    obj->auth_required = kislayphp_env_bool("KISLAY_GATEWAY_AUTH_REQUIRED", false);
    obj->auth_bearer_token = kislayphp_env_string("KISLAY_GATEWAY_AUTH_TOKEN", "");
    obj->auth_exclude_prefixes = kislayphp_split_csv(
        kislayphp_env_string("KISLAY_GATEWAY_AUTH_EXCLUDE", "/health,/ready,/metrics"));
    obj->jwt_secret = kislayphp_env_string("KISLAY_GATEWAY_JWT_SECRET", "");
    obj->auth_user_header = "X-Authenticated-User";
    obj->trace_enabled = kislayphp_env_bool("KISLAY_GATEWAY_TRACE_ENABLED", false);
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
    obj->native_services.~shared_ptr();
    obj->circuit_map_lock.~shared_mutex();
    obj->circuit_states.~unordered_map();
    using RLShardsArray = std::array<RateLimitShard, RATE_LIMIT_SHARDS>;
    obj->rate_limit_shards.~RLShardsArray();
    obj->auth_user_header.~basic_string();
    obj->jwt_secret.~basic_string();
    obj->auth_exclude_prefixes.~vector();
    obj->auth_bearer_token.~basic_string();
    obj->frozen_prefix.~vector();
    obj->frozen_exact.~unordered_map();
    obj->route_table_frozen.~atomic<bool>();
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

// Hot-path variant: real HTTP clients almost always send an already-uppercase
// verb (GET/POST/...), so mutate in place instead of allocating+copying via
// kislayphp_to_upper on every single request.
static void kislayphp_uppercase_inplace(std::string &value) {
    for (char &c : value) {
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>(c - ('a' - 'A'));
        }
    }
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
    // Fast path: base_path=="/" (the overwhelming majority of routes, since no
    // sub-path rewriting is configured) means the joined path is always just
    // `path` unchanged — skip the substr()+concatenation below entirely.
    if (base.size() == 1 && base[0] == '/') {
        return path;
    }
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
    const std::size_t prefix_len = pattern.size() - 1;
    if (prefix_len == 0) {
        return true;
    }
    if (path.size() < prefix_len) {
        return false;
    }
    // Compare path's and pattern's leading prefix_len characters directly —
    // pattern.substr(0, prefix_len) would allocate a temporary string on
    // every call, every request that falls through to a wildcard route scan.
    return path.compare(0, prefix_len, pattern, 0, prefix_len) == 0;
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

// Pre-computes "host:port" (upstream_key, used for the Host header and
// circuit-breaker keying) and "host:port[s]" (pool_key, used for connection
// pooling) once, at route-registration time, so the request hot path never
// has to allocate/concatenate these strings. Must be called for every route
// that resolves to a concrete host:port (static addRoute targets, each
// registerService() pool member, and setFallbackTarget()) — dynamic
// use_service routes resolve their backend per-request and don't need this.
static void kislayphp_compute_route_keys(kislayphp_gateway_route &route) {
    route.upstream_key = route.host + ":" + std::to_string(route.port);
    route.pool_key = route.upstream_key + (route.use_tls ? "s" : "");
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

static bool kislayphp_resolve_native_service(php_kislayphp_gateway_t *gateway,
                                             const std::string &service,
                                             kislayphp_gateway_route *resolved) {
    if (gateway == nullptr || resolved == nullptr) {
        return false;
    }

    std::shared_ptr<kislayphp_native_service_registry> registry = std::atomic_load(&gateway->native_services);
    if (!registry) {
        return false;
    }

    auto it = registry->find(service);
    if (it == registry->end() || !it->second || it->second->targets.empty()) {
        return false;
    }

    const std::shared_ptr<kislayphp_native_service_entry> &entry = it->second;
    const uint32_t slot = entry->next_index.fetch_add(1, std::memory_order_relaxed);
    *resolved = entry->targets[slot % entry->targets.size()];
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
                                        const std::string &secret,
                                        std::string &sub_out,
                                        std::string &roles_out) {
    sub_out.clear();
    roles_out.clear();

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
                // Allow 30s clock-skew tolerance
                if (exp_val < (static_cast<long long>(std::time(nullptr)) - 30LL)) {
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

    // Extract sub claim
    auto extract_string_claim = [&](const std::string &json,
                                    const std::string &key) -> std::string {
        std::string needle = "\"" + key + "\"";
        size_t p = json.find(needle);
        if (p == std::string::npos) return "";
        size_t c = json.find(':', p + needle.size());
        if (c == std::string::npos) return "";
        size_t q1 = json.find('"', c + 1);
        if (q1 == std::string::npos) return "";
        size_t q2 = json.find('"', q1 + 1);
        if (q2 == std::string::npos) return "";
        return json.substr(q1 + 1, q2 - q1 - 1);
    };
    sub_out = extract_string_claim(payload_json, "sub");

    // Extract roles claim (array of strings, comma-joined)
    std::string roles_needle = "\"roles\"";
    size_t roles_pos = payload_json.find(roles_needle);
    if (roles_pos != std::string::npos) {
        size_t bracket = payload_json.find('[', roles_pos + roles_needle.size());
        if (bracket != std::string::npos) {
            size_t end_bracket = payload_json.find(']', bracket + 1);
            if (end_bracket != std::string::npos) {
                std::string arr = payload_json.substr(bracket + 1, end_bracket - bracket - 1);
                size_t p = 0;
                while (p < arr.size()) {
                    size_t q1 = arr.find('"', p);
                    if (q1 == std::string::npos) break;
                    size_t q2 = arr.find('"', q1 + 1);
                    if (q2 == std::string::npos) break;
                    if (!roles_out.empty()) roles_out += ',';
                    roles_out += arr.substr(q1 + 1, q2 - q1 - 1);
                    p = q2 + 1;
                }
            }
        }
    }

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
    getrandom(buf, bytes, 0);
#endif
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < bytes; i++) {
        result[i*2]   = hex[buf[i] >> 4];
        result[i*2+1] = hex[buf[i] & 0xf];
    }
    return result;
}

#include <sys/poll.h>
#include <unistd.h>

// Safe connection liveness check (no UB internal struct access)
static bool kislay_is_conn_alive(struct mg_connection *conn) {
    // CivetWeb does not expose a public API to get the raw fd.
    // We rely on mg_read returning <=0 (which CivetWeb sets on close).
    // For pooled keep-alive validation we use a zero-timeout mg_read probe
    // via MSG_PEEK through a non-blocking wrapper if available.
    // Fallback: optimistically assume alive — broken connections are
    // detected by the next mg_printf/mg_read failure in do_proxy.
    if (!conn) return false;
    return true;
}

struct PooledConnection {
    struct mg_connection *conn;
    std::chrono::steady_clock::time_point last_used;
    std::string key;
};

class GatewayConnectionPool {
public:
    static GatewayConnectionPool& get() {
        static thread_local GatewayConnectionPool instance;
        return instance;
    }

    ~GatewayConnectionPool() {
        clear();
    }

    struct mg_connection* acquire(const std::string& pool_key) {
        auto it = pool.find(pool_key);
        if (it != pool.end() && !it->second.empty()) {
            auto& conns = it->second;
            while (!conns.empty()) {
                auto pconn = std::move(conns.back());
                conns.pop_back();
                total_connections--;

                // Idle timeout: 60 seconds
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(now - pconn.last_used).count() > 60) {
                    mg_close_connection(pconn.conn);
                    continue;
                }

                if (kislay_is_conn_alive(pconn.conn)) {
                    return pconn.conn;
                } else {
                    mg_close_connection(pconn.conn);
                }
            }
        }
        return nullptr;
    }

    void release(struct mg_connection* conn, const std::string& pool_key) {
        if (!conn) return;

        // Enforce total limit: 128 connections per thread
        if (total_connections >= 128) {
            // Find oldest connection across all hosts
            std::string oldest_key;
            auto oldest_time = std::chrono::steady_clock::time_point::max();
            
            for (auto& entry : pool) {
                if (!entry.second.empty()) {
                    if (entry.second.front().last_used < oldest_time) {
                        oldest_time = entry.second.front().last_used;
                        oldest_key = entry.first;
                    }
                }
            }
            
            if (!oldest_key.empty()) {
                auto& oldest_conns = pool[oldest_key];
                auto old_pconn = std::move(oldest_conns.front());
                oldest_conns.erase(oldest_conns.begin());
                mg_close_connection(old_pconn.conn);
                total_connections--;
            }
        }

        auto& conns = pool[pool_key];
        if (conns.size() >= 16) { // Max 16 connections per host per thread
            auto old_pconn = std::move(conns.front());
            conns.erase(conns.begin());
            mg_close_connection(old_pconn.conn);
            total_connections--;
        }

        conns.push_back({conn, std::chrono::steady_clock::now(), pool_key});
        total_connections++;
    }

    void clear() {
        for (auto& entry : pool) {
            for (auto& pconn : entry.second) {
                mg_close_connection(pconn.conn);
            }
        }
        pool.clear();
        total_connections = 0;
    }

private:
    std::unordered_map<std::string, std::vector<PooledConnection>> pool;
    size_t total_connections = 0;
};

static bool kislayphp_proxy_request(struct mg_connection *conn,
                                    const struct mg_request_info *info,
                                    const kislayphp_gateway_route &route,
                                    size_t max_body_bytes,
                                    int *status_code_out,
                                    const std::vector<std::pair<std::string,std::string>> &extra_headers = {},
                                    const char *client_ip = nullptr,
                                    const char *host_hdr = nullptr) {
    if (status_code_out != nullptr) {
        *status_code_out = 0;
    }
    if (max_body_bytes > 0 && info->content_length > static_cast<long long>(max_body_bytes)) {
        kislayphp_send_error(conn, 413, "Payload Too Large");
        if (status_code_out != nullptr) {
            *status_code_out = 413;
        }
        return false;
    }

    char error_buf[256] = {0};
    struct mg_connection *target = nullptr;
    bool reused = false;

    // Try to acquire from pool using pre-computed key
    const std::string &effective_pool_key =
        !route.pool_key.empty() ? route.pool_key
            : (route.host + ":" + std::to_string(route.port) + (route.use_tls ? "s" : ""));
    target = GatewayConnectionPool::get().acquire(effective_pool_key);
    if (target) {
        reused = true;
    } else {
        target = mg_connect_client(route.host.c_str(), route.port, route.use_tls ? 1 : 0, error_buf, sizeof(error_buf));
    }

    if (target == nullptr) {
        // NOT php_error_docref: this runs on an arbitrary civetweb worker thread.
        // php_error_docref ultimately calls into Zend's memory manager (_emalloc),
        // which has no per-thread isolation on an NTS build. Concurrent calls from
        // multiple worker threads corrupt the shared Zend heap and trigger
        // zend_mm_panic() -> abort(), crashing the whole process. Plain stderr
        // logging never touches the Zend engine, so it's safe from any thread.
        std::fprintf(stderr, "[kislayphp_gateway] WARNING: Upstream connect failed for %s://%s:%d (%s)\n",
                     route.use_tls ? "https" : "http",
                     route.host.c_str(),
                     route.port,
                     error_buf[0] != '\0' ? error_buf : "unknown error");
        kislayphp_send_error(conn, 502, "Upstream connect failed");
        if (status_code_out != nullptr) {
            *status_code_out = 502;
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
    bool body_consumed = false;

    auto do_proxy = [&](struct mg_connection *tgt) mutable -> bool {
        // Build entire request header block into one buffer — single mg_write syscall
        // instead of 8-15 mg_printf calls, saving ~1-3µs in syscall overhead.
        thread_local std::string req_buf;
        req_buf.clear();
        req_buf.reserve(512);

        req_buf += method;
        req_buf += ' ';
        req_buf += target_path;
        req_buf += " HTTP/1.1\r\nHost: ";
        req_buf += route.upstream_key;  // pre-computed "host:port"
        req_buf += "\r\nConnection: keep-alive\r\nX-Forwarded-For: ";
        req_buf += client_ip ? client_ip : kislayphp_client_identifier(info).c_str();
        req_buf += "\r\nX-Forwarded-Proto: ";
        req_buf += route.use_tls ? "https" : "http";
        req_buf += "\r\nX-Forwarded-Host: ";
        req_buf += host_hdr ? host_hdr : "unknown";
        req_buf += "\r\n";

        for (const auto &h : extra_headers) {
            req_buf += h.first;
            req_buf += ": ";
            req_buf += h.second;
            req_buf += "\r\n";
        }

        bool has_content_length = false;
        for (int i = 0; i < info->num_headers; ++i) {
            const char *name = info->http_headers[i].name;
            const char *value = info->http_headers[i].value;
            if (name == nullptr || value == nullptr) continue;
            if (kislayphp_skip_upstream_header(name)) continue;
            if ((name[0] | 0x20) == 'c' && ::strcasecmp(name, "Content-Length") == 0) has_content_length = true;
            req_buf += name;
            req_buf += ": ";
            req_buf += value;
            req_buf += "\r\n";
        }

        if (!has_content_length && info->content_length >= 0) {
            char cl_buf[32];
            snprintf(cl_buf, sizeof(cl_buf), "%lld", static_cast<long long>(info->content_length));
            req_buf += "Content-Length: ";
            req_buf += cl_buf;
            req_buf += "\r\n";
        }
        req_buf += "\r\n";

        if (mg_write(tgt, req_buf.data(), req_buf.size()) <= 0) return false;

        if (info->content_length > 0) {
            char buffer[16384];
            long long remaining = info->content_length;
            while (remaining > 0) {
                int to_read = remaining > (long long)sizeof(buffer) ? (int)sizeof(buffer) : (int)remaining;
                int read_now = mg_read(conn, buffer, to_read);
                if (read_now > 0) body_consumed = true;
                if (read_now <= 0) break;
                if (mg_write(tgt, buffer, (size_t)read_now) <= 0) return false;
                remaining -= read_now;
            }
        }

        if (mg_get_response(tgt, error_buf, sizeof(error_buf), 10000) < 0) {
            return false;
        }
        return true;
    };

    if (!do_proxy(target)) {
        mg_close_connection(target);
        if (reused && !body_consumed) {
            // Reused connection failed before we consumed body, try once more with a fresh one
            target = mg_connect_client(route.host.c_str(), route.port, route.use_tls ? 1 : 0, error_buf, sizeof(error_buf));
            if (target && do_proxy(target)) {
                // Success with fresh connection
            } else {
                if (target) mg_close_connection(target);
                kislayphp_send_error(conn, 502, "Upstream response failed");
                if (status_code_out != nullptr) *status_code_out = 502;
                return false;
            }
        } else {
            kislayphp_send_error(conn, 502, "Upstream response failed");
            if (status_code_out != nullptr) *status_code_out = 502;
            return false;
        }
    }

    const struct mg_response_info *resp_info = mg_get_response_info(target);
    int status_code = resp_info ? resp_info->status_code : 502;
    if (status_code_out != nullptr) *status_code_out = status_code;
    const char *status_text = (resp_info && resp_info->status_text) ? resp_info->status_text : "Bad Gateway";

    bool resp_has_length = false;
    bool upstream_keep_alive = false;
    if (resp_info && resp_info->http_version &&
        (std::strcmp(resp_info->http_version, "1.1") == 0 || std::strcmp(resp_info->http_version, "1.2") == 0)) {
        upstream_keep_alive = true;
    }

    // Buffer entire response header block for a single downstream write syscall.
    thread_local std::string resp_buf;
    resp_buf.clear();
    resp_buf.reserve(256);
    resp_buf += "HTTP/1.1 ";
    char sc_buf[16];
    snprintf(sc_buf, sizeof(sc_buf), "%d ", status_code);
    resp_buf += sc_buf;
    resp_buf += status_text;
    resp_buf += "\r\n";

    if (resp_info) {
        for (int i = 0; i < resp_info->num_headers; ++i) {
            const char *name = resp_info->http_headers[i].name;
            const char *value = resp_info->http_headers[i].value;
            if (name == nullptr || value == nullptr) continue;
            if (::strcasecmp(name, "Connection") == 0) {
                if (::strcasecmp(value, "close") == 0) upstream_keep_alive = false;
                else if (::strcasecmp(value, "keep-alive") == 0) upstream_keep_alive = true;
                continue;
            }
            if (kislayphp_is_hop_header(name)) continue;
            if (::strcasecmp(name, "Content-Length") == 0) resp_has_length = true;
            resp_buf += name;
            resp_buf += ": ";
            resp_buf += value;
            resp_buf += "\r\n";
        }
        if (!resp_has_length && resp_info->content_length >= 0) {
            char cl_buf[32];
            snprintf(cl_buf, sizeof(cl_buf), "%lld", static_cast<long long>(resp_info->content_length));
            resp_buf += "Content-Length: ";
            resp_buf += cl_buf;
            resp_buf += "\r\n";
            resp_has_length = true;
        }
    }
    const bool downstream_keep_alive =
        !kislayphp_request_wants_close(info) &&
        resp_has_length &&
        status_code != 101;
    resp_buf += "Connection: ";
    resp_buf += downstream_keep_alive ? "keep-alive" : "close";
    resp_buf += "\r\n\r\n";
    mg_write(conn, resp_buf.data(), resp_buf.size());

    char buffer[16384];
    int read_len = 0;
    bool read_ok = true;
    long long remaining = resp_info ? resp_info->content_length : -1;

    if (remaining >= 0) {
        while (remaining > 0) {
            int to_read = remaining > (long long)sizeof(buffer) ? (int)sizeof(buffer) : (int)remaining;
            read_len = mg_read(target, buffer, to_read);
            if (read_len <= 0) {
                read_ok = (remaining == 0);
                break;
            }
            if (mg_write(conn, buffer, static_cast<size_t>(read_len)) <= 0) {
                read_ok = false;
                break;
            }
            remaining -= read_len;
        }
    } else {
        // No content length, read until close
        while ((read_len = mg_read(target, buffer, sizeof(buffer))) > 0) {
            if (mg_write(conn, buffer, static_cast<size_t>(read_len)) <= 0) {
                read_ok = false;
                break;
            }
        }
        if (read_len < 0) read_ok = false;
        upstream_keep_alive = false; // Cannot keep-alive without content-length unless chunked
    }

    if (upstream_keep_alive && read_ok) {
        GatewayConnectionPool::get().release(target, effective_pool_key);
    } else {
        mg_close_connection(target);
    }
    return read_ok;
}

// Returns the per-host circuit-breaker state, creating it on first access.
// Fast path: shared (reader) lock — multiple threads find their pre-populated entry
// without blocking each other. Slow path: exclusive lock + double-check for the rare
// dynamic-service host not yet in the map.
static std::shared_ptr<PerHostCircuitState> kislayphp_get_circuit_state(
        php_kislayphp_gateway_t *gw, const std::string &key) {
    {
        std::shared_lock<std::shared_mutex> rl(gw->circuit_map_lock);
        auto it = gw->circuit_states.find(key);
        if (it != gw->circuit_states.end()) return it->second;
    }
    std::unique_lock<std::shared_mutex> wl(gw->circuit_map_lock);
    auto &slot = gw->circuit_states[key];
    if (!slot) slot = std::make_shared<PerHostCircuitState>();
    return slot;
}

static int kislayphp_gateway_begin_request(struct mg_connection *conn) {
    const struct mg_request_info *info = mg_get_request_info(conn);
    if (info == nullptr || info->user_data == nullptr) {
        return 0;
    }

    auto *gateway = static_cast<php_kislayphp_gateway_t *>(info->user_data);
    std::string method = info->request_method ? info->request_method : "";
    kislayphp_uppercase_inplace(method);
    std::string path = info->local_uri ? info->local_uri : (info->request_uri ? info->request_uri : "");

    // Single-pass header extraction: scan request headers once for all handler decisions.
    const char *hdr_authorization   = nullptr;
    const char *hdr_x_forwarded_for = nullptr;
    const char *hdr_traceparent     = nullptr;
    const char *hdr_tracestate      = nullptr;
    const char *hdr_host            = nullptr;
    for (int i = 0; i < info->num_headers; ++i) {
        const char *n = info->http_headers[i].name;
        const char *v = info->http_headers[i].value;
        if (n == nullptr || v == nullptr) continue;
        if      (!hdr_authorization   && ::strcasecmp(n, "Authorization")   == 0) hdr_authorization   = v;
        else if (!hdr_x_forwarded_for && ::strcasecmp(n, "X-Forwarded-For") == 0) hdr_x_forwarded_for = v;
        else if (!hdr_traceparent     && ::strcasecmp(n, "traceparent")      == 0) hdr_traceparent     = v;
        else if (!hdr_tracestate      && ::strcasecmp(n, "tracestate")       == 0) hdr_tracestate      = v;
        else if (!hdr_host            && ::strcasecmp(n, "Host")             == 0) hdr_host            = v;
    }

    // Compute client identifier once — used for rate-limit key and X-Forwarded-For.
    std::string client_id;
    if (hdr_x_forwarded_for != nullptr && *hdr_x_forwarded_for != '\0') {
        const char *comma = std::strchr(hdr_x_forwarded_for, ',');
        if (comma != nullptr) {
            const char *end = comma;
            while (end > hdr_x_forwarded_for &&
                   std::isspace(static_cast<unsigned char>(*(end - 1))))
                --end;
            client_id.assign(hdr_x_forwarded_for, end);
        } else {
            client_id = kislayphp_trim(std::string(hdr_x_forwarded_for));
        }
    } else {
        client_id.assign(info->remote_addr ? info->remote_addr : "unknown");
    }

    // Auth check: JWT (HS256) when jwt_secret is set; legacy bearer token otherwise.
    // Validated sub/roles are forwarded as upstream headers via extra_proxy_headers.
    // thread_local: civetweb threads process one request at a time, so reusing the
    // vector's already-grown capacity avoids a heap allocation on every request
    // (most requests carry no auth/tracing headers and never need >0 entries).
    thread_local std::vector<std::pair<std::string,std::string>> extra_proxy_headers;
    extra_proxy_headers.clear();

    if (gateway->auth_required) {
        if (!kislay_gateway_path_excluded(path, gateway->auth_exclude_prefixes)) {
            const char *auth_hdr = hdr_authorization;

            if (!gateway->jwt_secret.empty()) {
                // JWT validation mode (HS256)
                std::string jwt_sub;
                std::string jwt_roles;
                bool valid = false;
                if (auth_hdr != nullptr && std::strncmp(auth_hdr, "Bearer ", 7) == 0) {
                    std::string token(auth_hdr + 7);
                    valid = kislay_gateway_validate_jwt(token, gateway->jwt_secret,
                                                        jwt_sub, jwt_roles);
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
                // Inject validated claims as upstream headers
                if (!jwt_sub.empty()) {
                    extra_proxy_headers.emplace_back(gateway->auth_user_header, jwt_sub);
                }
                if (!jwt_roles.empty()) {
                    extra_proxy_headers.emplace_back("X-Auth-Roles", jwt_roles);
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
        auto now_tp = std::chrono::steady_clock::now();
        int64_t now_ms = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now_tp.time_since_epoch()).count());
        int64_t window_ms = static_cast<int64_t>(gateway->rate_limit_window_seconds) * 1000LL;
        // Hash directly from the two string components — no heap allocation.
        uint64_t rl_key = kislayphp_rl_hash(client_id.data(), client_id.size(),
                                             method.data(), method.size());

        // Prune one shard per 16384 requests to bound map growth under DDoS.
        // Pruning is done before acquiring the request shard so the two lock
        // acquisitions are independent even when they target the same shard.
        uint64_t cnt = gateway->rate_limit_request_counter.fetch_add(1, std::memory_order_relaxed);
        if ((cnt & 0x3FFF) == 0 && cnt > 0) {
            size_t prune_idx = (cnt >> 14) & (RATE_LIMIT_SHARDS - 1);
            std::lock_guard<std::mutex> pg(gateway->rate_limit_shards[prune_idx].lock);
            auto &pe = gateway->rate_limit_shards[prune_idx].entries;
            for (auto it = pe.begin(); it != pe.end(); ) {
                if ((now_ms - it->second.window_start_ms) > window_ms * 2)
                    it = pe.erase(it);
                else
                    ++it;
            }
        }

        size_t shard_idx = rl_key & (RATE_LIMIT_SHARDS - 1);
        std::lock_guard<std::mutex> guard(gateway->rate_limit_shards[shard_idx].lock);
        auto &entry = gateway->rate_limit_shards[shard_idx].entries[rl_key];
        if (entry.window_start_ms == 0 || (now_ms - entry.window_start_ms) >= window_ms) {
            entry.window_start_ms = now_ms;
            entry.count = 0;
        }
        if (entry.count >= gateway->rate_limit_requests) {
            kislayphp_send_error(conn, 429, "Rate limit exceeded");
            return 1;
        }
        entry.count++;
    }

    // W3C Trace Context: forward or generate traceparent/tracestate for upstream
    {
        const char *tp_hdr = hdr_traceparent;
        const char *ts_hdr = hdr_tracestate;
        if (tp_hdr) {
            extra_proxy_headers.emplace_back("traceparent", std::string(tp_hdr));
        } else if (gateway->trace_enabled) {
            // No incoming traceparent — generate one so downstream services have trace context
            std::string trace_id = kislay_gw_random_hex(16);
            std::string span_id  = kislay_gw_random_hex(8);
            std::string new_tp   = "00-" + trace_id + "-" + span_id + "-01";
            extra_proxy_headers.emplace_back("traceparent", new_tp);
        }
        if (ts_hdr) {
            extra_proxy_headers.emplace_back("tracestate", std::string(ts_hdr));
        }
    }

    kislayphp_gateway_route match;
    bool found = false;
    if (gateway->route_table_frozen.load(std::memory_order_acquire)) {
        // Lock-free hot path: O(1) hash lookup, then short prefix scan.
        // thread_local: civetweb threads handle one request at a time, so reusing
        // the string's already-grown capacity avoids a heap allocation per request.
        thread_local std::string key;
        key.clear();
        key = method;
        key += '\0';
        key += path;
        auto it = gateway->frozen_exact.find(key);
        if (it != gateway->frozen_exact.end()) {
            match = it->second;
            found = true;
        } else {
            for (const auto &r : gateway->frozen_prefix) {
                if ((r.method == method || r.method == "*") && kislayphp_path_matches(r.path, path)) {
                    match = r;
                    found = true;
                    break;
                }
            }
        }
        if (!found && gateway->has_fallback) {
            match = gateway->fallback_route;
            found = true;
        }
    } else {
        // Slow path: locked linear scan (only reachable before listen() returns).
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
    }

    if (!found) {
        kislayphp_send_error(conn, 404, "Not Found");
        return 1;
    }

    if (match.use_service) {
        kislayphp_gateway_route resolved;
        bool native_ok = kislayphp_resolve_native_service(gateway, match.service, &resolved);
        std::string rpc_target;
        bool rpc_ok = false;
        zval resolver;
        ZVAL_UNDEF(&resolver);
        bool has_resolver = false;
        if (!native_ok) {
            std::lock_guard<std::mutex> guard(gateway->lock);
            if (gateway->has_resolver) {
                ZVAL_COPY(&resolver, &gateway->resolver);
                has_resolver = true;
            }
        }
#ifdef KISLAYPHP_RPC
        if (!native_ok && !has_resolver && kislayphp_rpc_enabled()) {
            std::string error;
            rpc_ok = kislayphp_rpc_resolve_service(match.service, &rpc_target, &error);
        }
#endif

        if (!native_ok) {
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
                    // See the comment at the "Upstream connect failed" warning above:
                    // php_error_docref is unsafe from a civetweb worker thread on NTS.
                    // (Note: calling the PHP resolver callback itself via kislayphp_call_php
                    // just above is its own, separate, pre-existing thread-safety concern —
                    // out of scope here since this path isn't exercised by native/registered
                    // services, only by the PHP-callback resolver fallback.)
                    std::fprintf(stderr, "[kislayphp_gateway] WARNING: Gateway resolver failure: %s\n", resolver_error.c_str());
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

            resolved = match;
            resolved.target = target;
            resolved.use_service = false;
            if (!kislayphp_parse_target(resolved.target, resolved)) {
                kislayphp_send_error(conn, 502, "Invalid upstream target");
                return 1;
            }
            kislayphp_compute_route_keys(resolved);
        }
        if (gateway->circuit_breaker_enabled) {
            int64_t now_ms = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
            std::string upstream_key = resolved.host + ":" + std::to_string(resolved.port);
            auto cb_state = kislayphp_get_circuit_state(gateway, upstream_key);
            if (cb_state->open_until_ms.load(std::memory_order_acquire) > now_ms) {
                kislayphp_send_error(conn, 503, "Circuit breaker open");
                return 1;
            }

            int upstream_status = 0;
            bool ok_proxy = kislayphp_proxy_request(conn, info, resolved, gateway->max_body_bytes, &upstream_status, extra_proxy_headers, client_id.c_str(), hdr_host);
            bool failed = !ok_proxy || upstream_status >= 500;
            if (failed) {
                zend_long f = cb_state->failures.fetch_add(1, std::memory_order_acq_rel) + 1;
                if (f >= gateway->circuit_failure_threshold) {
                    cb_state->open_until_ms.store(
                        now_ms + static_cast<int64_t>(gateway->circuit_open_seconds) * 1000LL,
                        std::memory_order_release);
                    cb_state->failures.store(0, std::memory_order_release);
                }
            } else {
                cb_state->failures.store(0, std::memory_order_release);
                cb_state->open_until_ms.store(0, std::memory_order_release);
            }
            return 1;
        }

        kislayphp_proxy_request(conn, info, resolved, gateway->max_body_bytes, nullptr, extra_proxy_headers, client_id.c_str(), hdr_host);
        return 1;
    }

    if (gateway->circuit_breaker_enabled) {
        int64_t now_ms = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
        auto cb_state = kislayphp_get_circuit_state(gateway, match.upstream_key);
        if (cb_state->open_until_ms.load(std::memory_order_acquire) > now_ms) {
            kislayphp_send_error(conn, 503, "Circuit breaker open");
            return 1;
        }

        int upstream_status = 0;
        bool ok_proxy = kislayphp_proxy_request(conn, info, match, gateway->max_body_bytes, &upstream_status, extra_proxy_headers, client_id.c_str(), hdr_host);
        bool failed = !ok_proxy || upstream_status >= 500;
        if (failed) {
            zend_long f = cb_state->failures.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (f >= gateway->circuit_failure_threshold) {
                cb_state->open_until_ms.store(
                    now_ms + static_cast<int64_t>(gateway->circuit_open_seconds) * 1000LL,
                    std::memory_order_release);
                cb_state->failures.store(0, std::memory_order_release);
            }
        } else {
            cb_state->failures.store(0, std::memory_order_release);
            cb_state->open_until_ms.store(0, std::memory_order_release);
        }
        return 1;
    }

    kislayphp_proxy_request(conn, info, match, gateway->max_body_bytes, nullptr, extra_proxy_headers, client_id.c_str(), hdr_host);
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_register_service, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, service, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, targets, IS_ARRAY, 0)
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

PHP_METHOD(KislayPHPGateway, registerService) {
    char *service = nullptr;
    size_t service_len = 0;
    zval *targets = nullptr;
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(service, service_len)
        Z_PARAM_ARRAY(targets)
    ZEND_PARSE_PARAMETERS_END();

    if (service_len == 0) {
        zend_throw_exception(zend_ce_exception, "Service name cannot be empty", 0);
        RETURN_FALSE;
    }

    std::shared_ptr<kislayphp_native_service_entry> entry = std::make_shared<kislayphp_native_service_entry>();
    entry->targets.reserve(zend_hash_num_elements(Z_ARRVAL_P(targets)));

    zval *item = nullptr;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(targets), item) {
        if (Z_TYPE_P(item) != IS_STRING) {
            zend_throw_exception(zend_ce_exception, "Service targets must be strings", 0);
            RETURN_FALSE;
        }
        kislayphp_gateway_route route;
        route.method = "*";
        route.path = "*";
        route.target.assign(Z_STRVAL_P(item), Z_STRLEN_P(item));
        route.service.assign(service, service_len);
        route.use_service = false;
        route.use_tls = false;
        if (!kislayphp_parse_target(route.target, route)) {
            zend_throw_exception(zend_ce_exception, "Invalid service target (expected http(s)://host[:port][/base])", 0);
            RETURN_FALSE;
        }
        kislayphp_compute_route_keys(route);
        entry->targets.push_back(std::move(route));
    } ZEND_HASH_FOREACH_END();

    if (entry->targets.empty()) {
        zend_throw_exception(zend_ce_exception, "At least one service target is required", 0);
        RETURN_FALSE;
    }

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    std::lock_guard<std::mutex> guard(obj->lock);
    std::shared_ptr<kislayphp_native_service_registry> current = std::atomic_load(&obj->native_services);
    std::shared_ptr<kislayphp_native_service_registry> next =
        current ? std::make_shared<kislayphp_native_service_registry>(*current)
                : std::make_shared<kislayphp_native_service_registry>();
    (*next)[std::string(service, service_len)] = entry;
    std::atomic_store(&obj->native_services, next);
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

    std::string listen_addr = std::string(host, host_len) + ":" + std::to_string(port);
    std::vector<const char *> options;
    options.push_back("listening_ports");
    options.push_back(listen_addr.c_str());
    std::string threads_value = std::to_string(obj->thread_count);
    options.push_back("num_threads");
    options.push_back(threads_value.c_str());
    options.push_back("enable_keep_alive");
    options.push_back("yes");
    options.push_back("keep_alive_timeout_ms");
    options.push_back("30000");
    options.push_back(nullptr);

    // Build frozen route table before starting threads so all reads are lock-free.
    // Exact paths go into an unordered_map (O(1)); wildcard paths (*) go into a
    // vector sorted longest-prefix-first so the most specific pattern wins.
    // Also pre-populate circuit_states for all static upstreams so the hot path
    // always hits the fast shared-lock read in kislayphp_get_circuit_state().
    {
        obj->frozen_exact.reserve(obj->routes.size());
        for (auto r : obj->routes) {
            if (!r.use_service) {
                r.upstream_key = r.host + ":" + std::to_string(r.port);
                r.pool_key     = r.upstream_key + (r.use_tls ? "s" : "");
            }
            if (!r.path.empty() && r.path.back() == '*') {
                obj->frozen_prefix.push_back(std::move(r));
            } else {
                std::string key;
                key.reserve(r.method.size() + 1 + r.path.size());
                key = r.method;
                key += '\0';
                key += r.path;
                obj->frozen_exact.emplace(std::move(key), std::move(r));
            }
        }
        std::sort(obj->frozen_prefix.begin(), obj->frozen_prefix.end(),
            [](const kislayphp_gateway_route &a, const kislayphp_gateway_route &b) {
                return a.path.size() > b.path.size();
            });
        // Pre-populate circuit_states for all known static upstreams. Runs before
        // mg_start() so no lock needed — guarantees the hot path always finds its
        // entry via the cheap shared_lock read, never the exclusive write path.
        if (obj->circuit_breaker_enabled) {
            for (const auto &pair : obj->frozen_exact) {
                const auto &r = pair.second;
                if (!r.use_service && !r.upstream_key.empty()) {
                    auto &slot = obj->circuit_states[r.upstream_key];
                    if (!slot) slot = std::make_shared<PerHostCircuitState>();
                }
            }
            for (const auto &r : obj->frozen_prefix) {
                if (!r.use_service && !r.upstream_key.empty()) {
                    auto &slot = obj->circuit_states[r.upstream_key];
                    if (!slot) slot = std::make_shared<PerHostCircuitState>();
                }
            }
            if (obj->has_fallback && !obj->fallback_route.use_service &&
                    !obj->fallback_route.upstream_key.empty()) {
                auto &slot = obj->circuit_states[obj->fallback_route.upstream_key];
                if (!slot) slot = std::make_shared<PerHostCircuitState>();
            }
        }
        obj->route_table_frozen.store(true, std::memory_order_release);
    }

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
    kislayphp_compute_route_keys(route);

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
    PHP_ME(KislayPHPGateway, registerService, arginfo_kislayphp_gateway_register_service, ZEND_ACC_PUBLIC)
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
