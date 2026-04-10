extern "C" {
#include "php.h"
#include "ext/standard/info.h"
#include "Zend/zend_exceptions.h"
}

#include "php_kislayphp_gateway.h"
#include "engine/epoll/epoll_server.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <atomic>
#include <chrono>
#include <civetweb.h>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
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
    bool discovery_enabled;
    std::string discovery_backend;
    std::string discovery_path;
    zend_long discovery_poll_ms;
    bool auth_required;
    std::string auth_bearer_token;
    std::vector<std::string> auth_exclude_prefixes;
    std::string jwt_secret;
    std::string auth_user_header;
    bool rate_limit_enabled;
    zend_long rate_limit_requests;
    zend_long rate_limit_window_seconds;
    std::unordered_map<std::string, kislayphp_rate_limit_entry> rate_limits;
    bool circuit_breaker_enabled;
    zend_long circuit_failure_threshold;
    zend_long circuit_open_seconds;
    std::unordered_map<std::string, kislayphp_circuit_state> circuit_states;
    std::unique_ptr<kislay::gateway::epoll::EpollServer> epoll_server;
    std::string runtime_engine_override;
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

static bool kislayphp_env_has_value(const char *name) {
    const char *value = std::getenv(name);
    return value != nullptr && *value != '\0';
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

static int kislayphp_normalize_native_worker_count(int requested, const char *source) {
    if (requested == 0) {
        return 0;
    }
    if (requested < 0) {
        php_error_docref(nullptr, E_WARNING, "%s: invalid worker count %d; using auto", source, requested);
        return 0;
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

static std::string kislayphp_to_upper(const std::string &value);
static int kislayphp_gateway_begin_request(struct mg_connection *conn);

static zend_object *kislayphp_gateway_create_object(zend_class_entry *ce) {
    php_kislayphp_gateway_t *obj = static_cast<php_kislayphp_gateway_t *>(
        ecalloc(1, sizeof(php_kislayphp_gateway_t) + zend_object_properties_size(ce)));
    zend_object_std_init(&obj->std, ce);
    object_properties_init(&obj->std, ce);
    new (&obj->routes) std::vector<kislayphp_gateway_route>();
    new (&obj->fallback_route) kislayphp_gateway_route();
    new (&obj->lock) std::mutex();
    new (&obj->native_services) std::shared_ptr<kislayphp_native_service_registry>();
    new (&obj->discovery_backend) std::string();
    new (&obj->discovery_path) std::string();
    new (&obj->auth_bearer_token) std::string();
    new (&obj->auth_exclude_prefixes) std::vector<std::string>();
    new (&obj->jwt_secret) std::string();
    new (&obj->auth_user_header) std::string();
    new (&obj->rate_limits) std::unordered_map<std::string, kislayphp_rate_limit_entry>();
    new (&obj->circuit_states) std::unordered_map<std::string, kislayphp_circuit_state>();
    new (&obj->epoll_server) std::unique_ptr<kislay::gateway::epoll::EpollServer>();
    new (&obj->runtime_engine_override) std::string();
    obj->ctx = nullptr;
    obj->running = false;
    obj->has_fallback = false;
    zend_long max_body = kislayphp_env_long("KISLAY_GATEWAY_MAX_BODY", 0);
    if (max_body < 0) {
        max_body = 0;
    }
    obj->max_body_bytes = static_cast<size_t>(max_body);
    if (kislayphp_env_has_value("KISLAY_GATEWAY_THREADS")) {
        zend_long threads = kislayphp_env_long("KISLAY_GATEWAY_THREADS", 1);
        obj->thread_count = kislayphp_normalize_native_worker_count(static_cast<int>(threads),
                                                                    "Kislay\\Gateway\\Gateway::__construct");
    } else {
        obj->thread_count = 0;
    }
    ZVAL_UNDEF(&obj->resolver);
    obj->has_resolver = false;
    obj->native_services = std::make_shared<kislayphp_native_service_registry>();
    obj->discovery_enabled = false;
    obj->discovery_backend = kislayphp_env_string("KISLAY_GATEWAY_DISCOVERY_BACKEND", "");
    obj->discovery_path = kislayphp_env_string("KISLAY_GATEWAY_DISCOVERY_PATH", "");
    obj->discovery_poll_ms = kislayphp_env_long("KISLAY_GATEWAY_DISCOVERY_POLL_MS", 1000);
    if (obj->discovery_poll_ms < 100) {
        obj->discovery_poll_ms = 100;
    }
    if (!obj->discovery_backend.empty() && obj->discovery_backend != "static" && obj->discovery_backend != "none") {
        obj->discovery_enabled = true;
    }
    obj->auth_required = kislayphp_env_bool("KISLAY_GATEWAY_AUTH_REQUIRED", false);
    obj->auth_bearer_token = kislayphp_env_string("KISLAY_GATEWAY_AUTH_TOKEN", "");
    obj->auth_exclude_prefixes = kislayphp_split_csv(
        kislayphp_env_string("KISLAY_GATEWAY_AUTH_EXCLUDE", "/health,/ready,/metrics"));
    obj->jwt_secret = kislayphp_env_string("KISLAY_GATEWAY_JWT_SECRET", "");
    obj->auth_user_header = "X-Authenticated-User";
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
    if (obj->epoll_server) {
        obj->epoll_server->Stop();
        obj->epoll_server.reset();
    }
    if (obj->has_resolver) {
        zval_ptr_dtor(&obj->resolver);
    }
    obj->epoll_server.~unique_ptr();
    obj->runtime_engine_override.~basic_string();
    obj->native_services.~shared_ptr();
    obj->discovery_path.~basic_string();
    obj->discovery_backend.~basic_string();
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

static bool kislayphp_gateway_is_running(const php_kislayphp_gateway_t *gateway) {
    return gateway != nullptr &&
           (gateway->ctx != nullptr || gateway->epoll_server.get() != nullptr || gateway->running);
}

static bool kislayphp_gateway_ensure_config_mutable(const php_kislayphp_gateway_t *gateway,
                                                    const char *source,
                                                    std::string *error_out) {
    if (!kislayphp_gateway_is_running(gateway)) {
        return true;
    }
    if (error_out != nullptr) {
        *error_out = std::string(source) + " cannot be changed after listen()";
    }
    return false;
}

static std::string kislayphp_gateway_runtime_engine(const php_kislayphp_gateway_t *gateway) {
    if (gateway != nullptr && !gateway->runtime_engine_override.empty()) {
        return gateway->runtime_engine_override;
    }
    return kislayphp_env_string("KISLAY_GATEWAY_ENGINE", "civetweb");
}

static bool kislayphp_gateway_add_route_internal(php_kislayphp_gateway_t *gateway,
                                                 const std::string &method,
                                                 const std::string &path,
                                                 const std::string &target,
                                                 std::string *error_out) {
    if (gateway == nullptr) {
        if (error_out != nullptr) {
            *error_out = "gateway is null";
        }
        return false;
    }
    if (!kislayphp_gateway_ensure_config_mutable(gateway, "addRoute()", error_out)) {
        return false;
    }

    kislayphp_gateway_route route;
    route.method.assign(kislayphp_to_upper(method));
    route.path = path.empty() ? "/" : path;
    route.target = target;
    route.use_service = false;
    route.use_tls = false;
    if (!kislayphp_parse_target(route.target, route)) {
        if (error_out != nullptr) {
            *error_out = "Invalid target (expected http(s)://host[:port][/base])";
        }
        return false;
    }

    std::lock_guard<std::mutex> guard(gateway->lock);
    gateway->routes.push_back(route);
    return true;
}

static bool kislayphp_gateway_add_service_route_internal(php_kislayphp_gateway_t *gateway,
                                                         const std::string &method,
                                                         const std::string &path,
                                                         const std::string &service,
                                                         std::string *error_out) {
    if (gateway == nullptr) {
        if (error_out != nullptr) {
            *error_out = "gateway is null";
        }
        return false;
    }
    if (!kislayphp_gateway_ensure_config_mutable(gateway, "addServiceRoute()", error_out)) {
        return false;
    }
    if (service.empty()) {
        if (error_out != nullptr) {
            *error_out = "Service name cannot be empty";
        }
        return false;
    }

    kislayphp_gateway_route route;
    route.method.assign(kislayphp_to_upper(method));
    route.path = path.empty() ? "/" : path;
    route.target.clear();
    route.service = service;
    route.use_service = true;
    route.use_tls = false;

    std::lock_guard<std::mutex> guard(gateway->lock);
    gateway->routes.push_back(route);
    return true;
}

static bool kislayphp_gateway_register_service_targets_internal(
    php_kislayphp_gateway_t *gateway,
    const std::string &service,
    const std::vector<std::string> &targets,
    std::string *error_out) {
    if (gateway == nullptr) {
        if (error_out != nullptr) {
            *error_out = "gateway is null";
        }
        return false;
    }
    if (!kislayphp_gateway_ensure_config_mutable(gateway, "registerService()", error_out)) {
        return false;
    }
    if (service.empty()) {
        if (error_out != nullptr) {
            *error_out = "Service name cannot be empty";
        }
        return false;
    }
    if (targets.empty()) {
        if (error_out != nullptr) {
            *error_out = "At least one service target is required";
        }
        return false;
    }

    std::shared_ptr<kislayphp_native_service_entry> entry = std::make_shared<kislayphp_native_service_entry>();
    entry->targets.reserve(targets.size());
    for (std::size_t i = 0; i < targets.size(); ++i) {
        kislayphp_gateway_route route;
        route.method = "*";
        route.path = "*";
        route.target = targets[i];
        route.service = service;
        route.use_service = false;
        route.use_tls = false;
        if (!kislayphp_parse_target(route.target, route)) {
            if (error_out != nullptr) {
                *error_out = "Invalid service target (expected http(s)://host[:port][/base])";
            }
            return false;
        }
        entry->targets.push_back(std::move(route));
    }

    std::lock_guard<std::mutex> guard(gateway->lock);
    std::shared_ptr<kislayphp_native_service_registry> current = std::atomic_load(&gateway->native_services);
    std::shared_ptr<kislayphp_native_service_registry> next =
        current ? std::make_shared<kislayphp_native_service_registry>(*current)
                : std::make_shared<kislayphp_native_service_registry>();
    (*next)[service] = entry;
    std::atomic_store(&gateway->native_services, next);
    return true;
}

static bool kislayphp_gateway_set_discovery_backend_internal(php_kislayphp_gateway_t *gateway,
                                                             zval *config,
                                                             std::string *error_out) {
    if (gateway == nullptr || config == nullptr || Z_TYPE_P(config) != IS_ARRAY) {
        if (error_out != nullptr) {
            *error_out = "Discovery backend config must be an array";
        }
        return false;
    }
    if (!kislayphp_gateway_ensure_config_mutable(gateway, "setDiscoveryBackend()", error_out)) {
        return false;
    }

    std::string backend = gateway->discovery_backend;
    std::string path = gateway->discovery_path;
    zend_long poll_ms = gateway->discovery_poll_ms;

    zval *value = zend_hash_str_find(Z_ARRVAL_P(config), "backend", sizeof("backend") - 1);
    if (value != nullptr) {
        if (Z_TYPE_P(value) != IS_STRING) {
            if (error_out != nullptr) {
                *error_out = "discovery backend must be a string";
            }
            return false;
        }
        backend.assign(Z_STRVAL_P(value), Z_STRLEN_P(value));
    }

    value = zend_hash_str_find(Z_ARRVAL_P(config), "path", sizeof("path") - 1);
    if (value != nullptr) {
        if (Z_TYPE_P(value) != IS_STRING) {
            if (error_out != nullptr) {
                *error_out = "discovery path must be a string";
            }
            return false;
        }
        path.assign(Z_STRVAL_P(value), Z_STRLEN_P(value));
    }

    value = zend_hash_str_find(Z_ARRVAL_P(config), "poll_ms", sizeof("poll_ms") - 1);
    if (value != nullptr) {
        if (Z_TYPE_P(value) != IS_LONG) {
            if (error_out != nullptr) {
                *error_out = "discovery poll_ms must be an integer";
            }
            return false;
        }
        poll_ms = Z_LVAL_P(value);
    }

    if (poll_ms < 100) {
        poll_ms = 100;
    }

    if (backend.empty() || backend == "none" || backend == "static") {
        std::lock_guard<std::mutex> guard(gateway->lock);
        gateway->discovery_enabled = false;
        gateway->discovery_backend = "static";
        gateway->discovery_path.clear();
        gateway->discovery_poll_ms = poll_ms;
        return true;
    }

    if (backend != "file") {
        if (error_out != nullptr) {
            *error_out = "unsupported discovery backend; use 'file' or 'static'";
        }
        return false;
    }
    if (path.empty()) {
        if (error_out != nullptr) {
            *error_out = "file discovery backend requires 'path'";
        }
        return false;
    }

    std::lock_guard<std::mutex> guard(gateway->lock);
    gateway->discovery_enabled = true;
    gateway->discovery_backend = backend;
    gateway->discovery_path = path;
    gateway->discovery_poll_ms = poll_ms;
    return true;
}

static bool kislayphp_gateway_set_fallback_target_internal(php_kislayphp_gateway_t *gateway,
                                                           const std::string &target,
                                                           std::string *error_out) {
    if (gateway == nullptr) {
        if (error_out != nullptr) {
            *error_out = "gateway is null";
        }
        return false;
    }
    if (!kislayphp_gateway_ensure_config_mutable(gateway, "setFallbackTarget()", error_out)) {
        return false;
    }
    kislayphp_gateway_route route;
    route.method = "*";
    route.path = "*";
    route.target = target;
    route.use_service = false;
    route.use_tls = false;
    if (!kislayphp_parse_target(route.target, route)) {
        if (error_out != nullptr) {
            *error_out = "Invalid fallback target (expected http(s)://host[:port][/base])";
        }
        return false;
    }

    std::lock_guard<std::mutex> guard(gateway->lock);
    gateway->fallback_route = route;
    gateway->has_fallback = true;
    return true;
}

static bool kislayphp_gateway_set_fallback_service_internal(php_kislayphp_gateway_t *gateway,
                                                            const std::string &service,
                                                            std::string *error_out) {
    if (gateway == nullptr) {
        if (error_out != nullptr) {
            *error_out = "gateway is null";
        }
        return false;
    }
    if (!kislayphp_gateway_ensure_config_mutable(gateway, "setFallbackService()", error_out)) {
        return false;
    }
    if (service.empty()) {
        if (error_out != nullptr) {
            *error_out = "Fallback service cannot be empty";
        }
        return false;
    }

    kislayphp_gateway_route route;
    route.method = "*";
    route.path = "*";
    route.target.clear();
    route.service = service;
    route.use_service = true;
    route.use_tls = false;

    std::lock_guard<std::mutex> guard(gateway->lock);
    gateway->fallback_route = route;
    gateway->has_fallback = true;
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

static bool kislayphp_build_epoll_config(php_kislayphp_gateway_t *gateway,
                                         const char *host,
                                         size_t host_len,
                                         zend_long port,
                                         kislay::gateway::epoll::EpollServerConfig *config,
                                         std::string *error_out) {
    if (gateway == nullptr || config == nullptr) {
        if (error_out != nullptr) {
            *error_out = "invalid epoll gateway configuration";
        }
        return false;
    }
    if (gateway->auth_required || gateway->rate_limit_enabled || gateway->circuit_breaker_enabled ||
        !gateway->jwt_secret.empty()) {
        if (error_out != nullptr) {
            *error_out = "epoll engine currently supports routing and proxying only; auth, rate limit, and circuit breaker stay on CivetWeb";
        }
        return false;
    }
    if (gateway->has_resolver) {
        if (error_out != nullptr) {
            *error_out = "epoll engine does not support PHP resolvers; use registerService()";
        }
        return false;
    }

    config->listen_host.assign(host, host_len);
    config->listen_port = static_cast<uint16_t>(port);
    config->worker_processes = gateway->thread_count > 0 ? gateway->thread_count : 0;
    config->max_body_bytes = gateway->max_body_bytes;
    if (gateway->discovery_enabled) {
        if (gateway->discovery_backend == "file") {
            config->discovery.enabled = true;
            config->discovery.backend = kislay::gateway::core::DiscoveryConfig::Backend::File;
            config->discovery.path = gateway->discovery_path;
            config->discovery.poll_ms =
                gateway->discovery_poll_ms > 0 ? static_cast<uint64_t>(gateway->discovery_poll_ms) : 1000ull;
        } else if (!gateway->discovery_backend.empty() && gateway->discovery_backend != "static") {
            if (error_out != nullptr) {
                *error_out = "unsupported native discovery backend: " + gateway->discovery_backend;
            }
            return false;
        }
    }

    std::lock_guard<std::mutex> guard(gateway->lock);
    for (std::size_t i = 0; i < gateway->routes.size(); ++i) {
        const kislayphp_gateway_route &route = gateway->routes[i];
        kislay::gateway::epoll::ControlRoute cp_route;
        cp_route.method = route.method;
        cp_route.path = route.path;
        cp_route.use_service = route.use_service;
        cp_route.service = route.service;
        cp_route.target.host = route.host;
        cp_route.target.port = static_cast<uint16_t>(route.port);
        cp_route.target.use_tls = route.use_tls;
        cp_route.target.base_path = route.base_path;
        config->snapshot.AddRoute(cp_route);
    }
    if (gateway->has_fallback) {
        kislay::gateway::epoll::ControlRoute fallback;
        fallback.method = gateway->fallback_route.method;
        fallback.path = gateway->fallback_route.path;
        fallback.use_service = gateway->fallback_route.use_service;
        fallback.service = gateway->fallback_route.service;
        fallback.target.host = gateway->fallback_route.host;
        fallback.target.port = static_cast<uint16_t>(gateway->fallback_route.port);
        fallback.target.use_tls = gateway->fallback_route.use_tls;
        fallback.target.base_path = gateway->fallback_route.base_path;
        config->snapshot.SetFallback(fallback);
    }

    std::shared_ptr<kislayphp_native_service_registry> current = std::atomic_load(&gateway->native_services);
    if (current) {
        for (kislayphp_native_service_registry::const_iterator it = current->begin(); it != current->end(); ++it) {
            if (!it->second) {
                continue;
            }
            kislay::gateway::epoll::ServiceRegistryEntry service_entry;
            service_entry.service = it->first;
            service_entry.targets.reserve(it->second->targets.size());
            for (std::size_t target_idx = 0; target_idx < it->second->targets.size(); ++target_idx) {
                const kislayphp_gateway_route &target_route = it->second->targets[target_idx];
                kislay::gateway::epoll::UpstreamTarget target;
                target.host = target_route.host;
                target.port = static_cast<uint16_t>(target_route.port);
                target.use_tls = target_route.use_tls;
                target.base_path = target_route.base_path;
                service_entry.targets.push_back(target);
            }
            config->snapshot.AddService(service_entry);
        }
    }
    config->snapshot.Finalize();
    return true;
}

static bool kislayphp_gateway_apply_start_config(php_kislayphp_gateway_t *gateway,
                                                 zval *config,
                                                 std::string *host_out,
                                                 zend_long *port_out,
                                                 std::string *error_out) {
    if (gateway == nullptr || config == nullptr || Z_TYPE_P(config) != IS_ARRAY ||
        host_out == nullptr || port_out == nullptr) {
        if (error_out != nullptr) {
            *error_out = "Invalid start configuration";
        }
        return false;
    }

    *host_out = "0.0.0.0";
    *port_out = 0;

    zval *value = zend_hash_str_find(Z_ARRVAL_P(config), "host", sizeof("host") - 1);
    if (value != nullptr) {
        if (Z_TYPE_P(value) != IS_STRING) {
            if (error_out != nullptr) {
                *error_out = "start config 'host' must be a string";
            }
            return false;
        }
        host_out->assign(Z_STRVAL_P(value), Z_STRLEN_P(value));
    }

    value = zend_hash_str_find(Z_ARRVAL_P(config), "port", sizeof("port") - 1);
    if (value == nullptr) {
        if (error_out != nullptr) {
            *error_out = "start config requires 'port'";
        }
        return false;
    }
    if (Z_TYPE_P(value) != IS_LONG) {
        if (error_out != nullptr) {
            *error_out = "start config 'port' must be an integer";
        }
        return false;
    }
    *port_out = Z_LVAL_P(value);

    value = zend_hash_str_find(Z_ARRVAL_P(config), "engine", sizeof("engine") - 1);
    if (value != nullptr) {
        if (Z_TYPE_P(value) != IS_STRING) {
            if (error_out != nullptr) {
                *error_out = "start config 'engine' must be a string";
            }
            return false;
        }
        gateway->runtime_engine_override.assign(Z_STRVAL_P(value), Z_STRLEN_P(value));
    }

    value = zend_hash_str_find(Z_ARRVAL_P(config), "workers", sizeof("workers") - 1);
    if (value != nullptr) {
        if (Z_TYPE_P(value) != IS_LONG) {
            if (error_out != nullptr) {
                *error_out = "start config 'workers' must be an integer";
            }
            return false;
        }
        gateway->thread_count = kislayphp_normalize_native_worker_count(
            static_cast<int>(Z_LVAL_P(value)), "Kislay\\Gateway\\Gateway::start");
    }

    value = zend_hash_str_find(Z_ARRVAL_P(config), "discovery", sizeof("discovery") - 1);
    if (value != nullptr) {
        if (!kislayphp_gateway_set_discovery_backend_internal(gateway, value, error_out)) {
            return false;
        }
    }

    value = zend_hash_str_find(Z_ARRVAL_P(config), "max_body_bytes", sizeof("max_body_bytes") - 1);
    if (value != nullptr) {
        if (Z_TYPE_P(value) != IS_LONG || Z_LVAL_P(value) < 0) {
            if (error_out != nullptr) {
                *error_out = "start config 'max_body_bytes' must be a non-negative integer";
            }
            return false;
        }
        gateway->max_body_bytes = static_cast<size_t>(Z_LVAL_P(value));
    }

    value = zend_hash_str_find(Z_ARRVAL_P(config), "routes", sizeof("routes") - 1);
    if (value != nullptr) {
        if (Z_TYPE_P(value) != IS_ARRAY) {
            if (error_out != nullptr) {
                *error_out = "start config 'routes' must be an array";
            }
            return false;
        }
        zval *route_entry = nullptr;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(value), route_entry) {
            if (Z_TYPE_P(route_entry) != IS_ARRAY) {
                if (error_out != nullptr) {
                    *error_out = "each route must be an array";
                }
                return false;
            }

            zval *method = zend_hash_str_find(Z_ARRVAL_P(route_entry), "method", sizeof("method") - 1);
            zval *path = zend_hash_str_find(Z_ARRVAL_P(route_entry), "path", sizeof("path") - 1);
            zval *target = zend_hash_str_find(Z_ARRVAL_P(route_entry), "target", sizeof("target") - 1);
            zval *service = zend_hash_str_find(Z_ARRVAL_P(route_entry), "service", sizeof("service") - 1);
            if (method == nullptr || path == nullptr || Z_TYPE_P(method) != IS_STRING || Z_TYPE_P(path) != IS_STRING) {
                if (error_out != nullptr) {
                    *error_out = "each route requires string 'method' and 'path'";
                }
                return false;
            }
            if ((target == nullptr && service == nullptr) || (target != nullptr && service != nullptr)) {
                if (error_out != nullptr) {
                    *error_out = "each route must define exactly one of 'target' or 'service'";
                }
                return false;
            }
            if (target != nullptr) {
                if (Z_TYPE_P(target) != IS_STRING) {
                    if (error_out != nullptr) {
                        *error_out = "route 'target' must be a string";
                    }
                    return false;
                }
                if (!kislayphp_gateway_add_route_internal(
                        gateway,
                        std::string(Z_STRVAL_P(method), Z_STRLEN_P(method)),
                        std::string(Z_STRVAL_P(path), Z_STRLEN_P(path)),
                        std::string(Z_STRVAL_P(target), Z_STRLEN_P(target)),
                        error_out)) {
                    return false;
                }
            } else {
                if (Z_TYPE_P(service) != IS_STRING) {
                    if (error_out != nullptr) {
                        *error_out = "route 'service' must be a string";
                    }
                    return false;
                }
                if (!kislayphp_gateway_add_service_route_internal(
                        gateway,
                        std::string(Z_STRVAL_P(method), Z_STRLEN_P(method)),
                        std::string(Z_STRVAL_P(path), Z_STRLEN_P(path)),
                        std::string(Z_STRVAL_P(service), Z_STRLEN_P(service)),
                        error_out)) {
                    return false;
                }
            }
        } ZEND_HASH_FOREACH_END();
    }

    value = zend_hash_str_find(Z_ARRVAL_P(config), "services", sizeof("services") - 1);
    if (value != nullptr) {
        if (Z_TYPE_P(value) != IS_ARRAY) {
            if (error_out != nullptr) {
                *error_out = "start config 'services' must be an array";
            }
            return false;
        }
        zend_string *service_name = nullptr;
        zval *service_targets = nullptr;
        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(value), service_name, service_targets) {
            if (service_name == nullptr || service_targets == nullptr || Z_TYPE_P(service_targets) != IS_ARRAY) {
                if (error_out != nullptr) {
                    *error_out = "each service entry must be an array of target strings";
                }
                return false;
            }
            std::vector<std::string> targets;
            targets.reserve(zend_hash_num_elements(Z_ARRVAL_P(service_targets)));
            zval *target_entry = nullptr;
            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(service_targets), target_entry) {
                if (Z_TYPE_P(target_entry) != IS_STRING) {
                    if (error_out != nullptr) {
                        *error_out = "service targets must be strings";
                    }
                    return false;
                }
                targets.push_back(std::string(Z_STRVAL_P(target_entry), Z_STRLEN_P(target_entry)));
            } ZEND_HASH_FOREACH_END();
            if (!kislayphp_gateway_register_service_targets_internal(
                    gateway, std::string(ZSTR_VAL(service_name), ZSTR_LEN(service_name)), targets, error_out)) {
                return false;
            }
        } ZEND_HASH_FOREACH_END();
    }

    zval *fallback_target = zend_hash_str_find(Z_ARRVAL_P(config), "fallback_target", sizeof("fallback_target") - 1);
    zval *fallback_service = zend_hash_str_find(Z_ARRVAL_P(config), "fallback_service", sizeof("fallback_service") - 1);
    if (fallback_target != nullptr && fallback_service != nullptr) {
        if (error_out != nullptr) {
            *error_out = "start config may define only one of 'fallback_target' or 'fallback_service'";
        }
        return false;
    }
    if (fallback_target != nullptr) {
        if (Z_TYPE_P(fallback_target) != IS_STRING) {
            if (error_out != nullptr) {
                *error_out = "start config 'fallback_target' must be a string";
            }
            return false;
        }
        if (!kislayphp_gateway_set_fallback_target_internal(
                gateway, std::string(Z_STRVAL_P(fallback_target), Z_STRLEN_P(fallback_target)), error_out)) {
            return false;
        }
    }
    if (fallback_service != nullptr) {
        if (Z_TYPE_P(fallback_service) != IS_STRING) {
            if (error_out != nullptr) {
                *error_out = "start config 'fallback_service' must be a string";
            }
            return false;
        }
        if (!kislayphp_gateway_set_fallback_service_internal(
                gateway, std::string(Z_STRVAL_P(fallback_service), Z_STRLEN_P(fallback_service)), error_out)) {
            return false;
        }
    }

    return true;
}

static bool kislayphp_gateway_listen_internal(php_kislayphp_gateway_t *gateway,
                                              const char *host,
                                              size_t host_len,
                                              zend_long port,
                                              std::string *error_out) {
    if (port <= 0 || port > 65535) {
        if (error_out != nullptr) {
            *error_out = "Invalid port";
        }
        return false;
    }
    if (gateway == nullptr) {
        if (error_out != nullptr) {
            *error_out = "Gateway object is null";
        }
        return false;
    }
    if (kislayphp_gateway_is_running(gateway)) {
        if (error_out != nullptr) {
            *error_out = "Gateway already running";
        }
        return false;
    }

    const std::string engine = kislayphp_gateway_runtime_engine(gateway);
    kislayphp_disable_stack_guard_for_nts("Kislay\\Gateway\\Gateway::listen");
    if (engine == "epoll" || engine == "kqueue" || engine == "auto" || engine == "native") {
        gateway->thread_count = kislayphp_normalize_native_worker_count(
            gateway->thread_count, "Kislay\\Gateway\\Gateway::listen");
        kislay::gateway::epoll::EpollServerConfig config;
        if (!kislayphp_build_epoll_config(gateway, host, host_len, port, &config, error_out)) {
            return false;
        }
        config.runtime_engine = engine;
        gateway->epoll_server.reset(new kislay::gateway::epoll::EpollServer(config));
        if (!gateway->epoll_server->Start(error_out)) {
            gateway->epoll_server.reset();
            return false;
        }
        gateway->running = true;
        return true;
    }

    if (gateway->thread_count == 0) {
        gateway->thread_count = 1;
    } else {
        gateway->thread_count = kislayphp_sanitize_thread_count(
            gateway->thread_count, "Kislay\\Gateway\\Gateway::listen");
    }
    std::string listen_addr = std::string(host, host_len) + ":" + std::to_string(port);
    std::vector<const char *> options;
    options.push_back("listening_ports");
    options.push_back(listen_addr.c_str());
    std::string threads_value = std::to_string(gateway->thread_count);
    options.push_back("num_threads");
    options.push_back(threads_value.c_str());
    options.push_back(nullptr);

    struct mg_callbacks callbacks;
    std::memset(&callbacks, 0, sizeof(callbacks));
    callbacks.begin_request = kislayphp_gateway_begin_request;

    gateway->ctx = mg_start(&callbacks, gateway, options.data());
    if (gateway->ctx == nullptr) {
        if (error_out != nullptr) {
            *error_out = "Failed to start gateway";
        }
        return false;
    }

    gateway->running = true;
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

#include <sys/poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

// Internal CivetWeb structures for connection pooling validation
namespace kislay_cv {
    typedef int SOCKET;
    union usa {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    };
    struct socket {
        SOCKET sock;
        union usa lsa;
        union usa rsa;
        unsigned char is_ssl;
        unsigned char ssl_redir;
        unsigned char is_optional;
        unsigned char in_use;
    };
    // Layout matching CivetWeb 1.17 mg_connection to access client.sock
    struct mg_connection_internal {
        int connection_type;
        int protocol_type;
        int request_state;
        // Padding for 8-byte alignment
        int padding;
        struct mg_request_info request_info;
        struct mg_response_info response_info;
        void *phys_ctx;
        void *dom_ctx;
        void *ssl;
        struct socket client;
    };
}

static int kislay_get_conn_fd(struct mg_connection *conn) {
    if (!conn) return -1;
    // We cast to our internal structure to access the socket
    auto *iconn = reinterpret_cast<kislay_cv::mg_connection_internal *>(conn);
    return iconn->client.sock;
}

static bool kislay_is_conn_alive(struct mg_connection *conn) {
    int fd = kislay_get_conn_fd(conn);
    if (fd < 0) return false;

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, 0);
    if (ret < 0) return false;
    if (ret > 0) {
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return false;
        // Check if there is data or EOF
        char buf;
        ssize_t r = recv(fd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
        if (r == 0) return false; // EOF
        if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return false;
    }
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

    struct mg_connection* acquire(const std::string& host, int port, bool use_tls) {
        std::string key = host + ":" + std::to_string(port) + (use_tls ? "s" : "");
        auto it = pool.find(key);
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

    void release(struct mg_connection* conn, const std::string& host, int port, bool use_tls) {
        if (!conn) return;
        
        std::string key = host + ":" + std::to_string(port) + (use_tls ? "s" : "");
        
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

        auto& conns = pool[key];
        if (conns.size() >= 16) { // Max 16 connections per host per thread
            auto old_pconn = std::move(conns.front());
            conns.erase(conns.begin());
            mg_close_connection(old_pconn.conn);
            total_connections--;
        }
        
        conns.push_back({conn, std::chrono::steady_clock::now(), key});
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
                                    const std::vector<std::pair<std::string,std::string>> &extra_headers = {}) {
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

    // Try to acquire from pool
    target = GatewayConnectionPool::get().acquire(route.host, route.port, route.use_tls);
    if (target) {
        reused = true;
    } else {
        target = mg_connect_client(route.host.c_str(), route.port, route.use_tls ? 1 : 0, error_buf, sizeof(error_buf));
    }

    if (target == nullptr) {
        php_error_docref(nullptr, E_WARNING, "Upstream connect failed for %s://%s:%d (%s)",
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
        mg_printf(tgt, "%s %s HTTP/1.1\r\n", method.c_str(), target_path.c_str());
        mg_printf(tgt, "Host: %s:%d\r\n", route.host.c_str(), route.port);
        mg_printf(tgt, "Connection: keep-alive\r\n");

        // X-Forwarded Headers
        mg_printf(tgt, "X-Forwarded-For: %s\r\n", kislayphp_client_identifier(info).c_str());
        mg_printf(tgt, "X-Forwarded-Proto: %s\r\n", route.use_tls ? "https" : "http");
        mg_printf(tgt, "X-Forwarded-Host: %s\r\n", info->http_headers[0].value ? info->http_headers[0].value : "unknown");

        for (const auto &h : extra_headers) {
            mg_printf(tgt, "%s: %s\r\n", h.first.c_str(), h.second.c_str());
        }

        bool has_content_length = false;
        for (int i = 0; i < info->num_headers; ++i) {
            const char *name = info->http_headers[i].name;
            const char *value = info->http_headers[i].value;
            if (name == nullptr || value == nullptr) continue;
            if (::strcasecmp(name, "Host") == 0 || 
                ::strcasecmp(name, "X-Forwarded-For") == 0 ||
                ::strcasecmp(name, "X-Forwarded-Proto") == 0 ||
                ::strcasecmp(name, "X-Forwarded-Host") == 0 ||
                kislayphp_is_hop_header(name)) {
                continue;
            }
            if (::strcasecmp(name, "Content-Length") == 0) has_content_length = true;
            mg_printf(tgt, "%s: %s\r\n", name, value);
        }

        if (!has_content_length && info->content_length >= 0) {
            mg_printf(tgt, "Content-Length: %lld\r\n", static_cast<long long>(info->content_length));
        }
        mg_printf(tgt, "\r\n");

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
    mg_printf(conn, "HTTP/1.1 %d %s\r\n", status_code, status_text);

    bool resp_has_length = false;
    bool upstream_keep_alive = false;
    if (resp_info && resp_info->http_version && 
        (std::strcmp(resp_info->http_version, "1.1") == 0 || std::strcmp(resp_info->http_version, "1.2") == 0)) {
        upstream_keep_alive = true;
    }

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
            mg_printf(conn, "%s: %s\r\n", name, value);
        }
        if (!resp_has_length && resp_info->content_length >= 0) {
            mg_printf(conn, "Content-Length: %lld\r\n", resp_info->content_length);
        }
    }
    mg_printf(conn, "Connection: close\r\n\r\n");

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
        GatewayConnectionPool::get().release(target, route.host, route.port, route.use_tls);
    } else {
        mg_close_connection(target);
    }
    return read_ok;
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

    // Auth check: JWT (HS256) when jwt_secret is set; legacy bearer token otherwise.
    // Validated sub/roles are forwarded as upstream headers via extra_proxy_headers.
    std::vector<std::pair<std::string,std::string>> extra_proxy_headers;

    if (gateway->auth_required) {
        if (!kislay_gateway_path_excluded(path, gateway->auth_exclude_prefixes)) {
            const char *auth_hdr = kislayphp_get_header(info, "Authorization");

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

    // W3C Trace Context: forward or generate traceparent/tracestate for upstream
    {
        const char *tp_hdr = kislayphp_get_header(info, "traceparent");
        const char *ts_hdr = kislayphp_get_header(info, "tracestate");
        if (tp_hdr) {
            extra_proxy_headers.emplace_back("traceparent", std::string(tp_hdr));
        } else {
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

            resolved = match;
            resolved.target = target;
            resolved.use_service = false;
            if (!kislayphp_parse_target(resolved.target, resolved)) {
                kislayphp_send_error(conn, 502, "Invalid upstream target");
                return 1;
            }
        }
        if (gateway->circuit_breaker_enabled) {
            std::time_t now = std::time(nullptr);
            std::string upstream_key = resolved.host + ":" + std::to_string(resolved.port);
            {
                std::lock_guard<std::mutex> guard(gateway->lock);
                auto it = gateway->circuit_states.find(upstream_key);
                if (it != gateway->circuit_states.end() && it->second.open_until > now) {
                    kislayphp_send_error(conn, 503, "Circuit breaker open");
                    return 1;
                }
            }

            int upstream_status = 0;
            bool ok_proxy = kislayphp_proxy_request(conn, info, resolved, gateway->max_body_bytes, &upstream_status, extra_proxy_headers);
            bool failed = !ok_proxy || upstream_status >= 500;
            std::lock_guard<std::mutex> guard(gateway->lock);
            auto &state = gateway->circuit_states[upstream_key];
            if (failed) {
                state.failures++;
                if (state.failures >= gateway->circuit_failure_threshold) {
                    state.open_until = now + gateway->circuit_open_seconds;
                    state.failures = 0;
                }
            } else {
                state.failures = 0;
                state.open_until = 0;
            }
            return 1;
        }

        kislayphp_proxy_request(conn, info, resolved, gateway->max_body_bytes, nullptr, extra_proxy_headers);
        return 1;
    }

    if (gateway->circuit_breaker_enabled) {
        std::time_t now = std::time(nullptr);
        std::string upstream_key = match.host + ":" + std::to_string(match.port);
        {
            std::lock_guard<std::mutex> guard(gateway->lock);
            auto it = gateway->circuit_states.find(upstream_key);
            if (it != gateway->circuit_states.end() && it->second.open_until > now) {
                kislayphp_send_error(conn, 503, "Circuit breaker open");
                return 1;
            }
        }

        int upstream_status = 0;
        bool ok_proxy = kislayphp_proxy_request(conn, info, match, gateway->max_body_bytes, &upstream_status, extra_proxy_headers);
        bool failed = !ok_proxy || upstream_status >= 500;
        std::lock_guard<std::mutex> guard(gateway->lock);
        auto &state = gateway->circuit_states[upstream_key];
        if (failed) {
            state.failures++;
            if (state.failures >= gateway->circuit_failure_threshold) {
                state.open_until = now + gateway->circuit_open_seconds;
                state.failures = 0;
            }
        } else {
            state.failures = 0;
            state.open_until = 0;
        }
        return 1;
    }

    kislayphp_proxy_request(conn, info, match, gateway->max_body_bytes, nullptr, extra_proxy_headers);
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_set_discovery_backend, 0, 0, 1)
    ZEND_ARG_TYPE_INFO(0, config, IS_ARRAY, 0)
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
    std::string error;
    if (!kislayphp_gateway_add_route_internal(obj,
                                              std::string(method, method_len),
                                              std::string(path, path_len),
                                              std::string(target, target_len),
                                              &error)) {
        zend_throw_exception(zend_ce_exception, error.c_str(), 0);
        RETURN_FALSE;
    }
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
    std::string error;
    if (!kislayphp_gateway_add_service_route_internal(obj,
                                                      std::string(method, method_len),
                                                      std::string(path, path_len),
                                                      std::string(service, service_len),
                                                      &error)) {
        zend_throw_exception(zend_ce_exception, error.c_str(), 0);
        RETURN_FALSE;
    }
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

    std::vector<std::string> target_values;
    target_values.reserve(zend_hash_num_elements(Z_ARRVAL_P(targets)));
    zval *item = nullptr;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(targets), item) {
        if (Z_TYPE_P(item) != IS_STRING) {
            zend_throw_exception(zend_ce_exception, "Service targets must be strings", 0);
            RETURN_FALSE;
        }
        target_values.emplace_back(Z_STRVAL_P(item), Z_STRLEN_P(item));
    } ZEND_HASH_FOREACH_END();

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    std::string error;
    if (!kislayphp_gateway_register_service_targets_internal(obj,
                                                             std::string(service, service_len),
                                                             target_values,
                                                             &error)) {
        zend_throw_exception(zend_ce_exception, error.c_str(), 0);
        RETURN_FALSE;
    }
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
    std::string error;
    if (!kislayphp_gateway_ensure_config_mutable(obj, "setThreads()", &error)) {
        zend_throw_exception(zend_ce_exception, error.c_str(), 0);
        RETURN_FALSE;
    }

    if (count == 0) {
        obj->thread_count = 0;
        RETURN_TRUE;
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
    std::string error;
    if (!kislayphp_gateway_ensure_config_mutable(obj, "setResolver()", &error)) {
        zend_throw_exception(zend_ce_exception, error.c_str(), 0);
        RETURN_FALSE;
    }
    std::lock_guard<std::mutex> guard(obj->lock);
    if (obj->has_resolver) {
        zval_ptr_dtor(&obj->resolver);
        obj->has_resolver = false;
    }
    ZVAL_COPY(&obj->resolver, resolver);
    obj->has_resolver = true;
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, setDiscoveryBackend) {
    zval *config = nullptr;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(config)
    ZEND_PARSE_PARAMETERS_END();

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    std::string error;
    if (!kislayphp_gateway_set_discovery_backend_internal(obj, config, &error)) {
        zend_throw_exception(zend_ce_exception, error.c_str(), 0);
        RETURN_FALSE;
    }
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

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    std::string error;
    if (!kislayphp_gateway_listen_internal(obj, host, host_len, port, &error)) {
        zend_throw_exception(zend_ce_exception, error.c_str(), 0);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, setFallbackTarget) {
    char *target = nullptr;
    size_t target_len = 0;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(target, target_len)
    ZEND_PARSE_PARAMETERS_END();

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    std::string error;
    if (!kislayphp_gateway_set_fallback_target_internal(obj,
                                                        std::string(target, target_len),
                                                        &error)) {
        zend_throw_exception(zend_ce_exception, error.c_str(), 0);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, setFallbackService) {
    char *service = nullptr;
    size_t service_len = 0;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(service, service_len)
    ZEND_PARSE_PARAMETERS_END();

    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    std::string error;
    if (!kislayphp_gateway_set_fallback_service_internal(obj,
                                                         std::string(service, service_len),
                                                         &error)) {
        zend_throw_exception(zend_ce_exception, error.c_str(), 0);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

PHP_METHOD(KislayPHPGateway, stop) {
    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    obj->running = false;
    if (obj->epoll_server) {
        obj->epoll_server->Stop();
        obj->epoll_server.reset();
    }
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
    std::string error;
    if (!kislayphp_gateway_ensure_config_mutable(obj, "requireAuth()", &error)) {
        zend_throw_exception(zend_ce_exception, error.c_str(), 0);
        RETURN_FALSE;
    }
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
    std::string error;
    if (!kislayphp_gateway_ensure_config_mutable(obj, "setAuthExclude()", &error)) {
        zend_throw_exception(zend_ce_exception, error.c_str(), 0);
        RETURN_FALSE;
    }
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
    PHP_ME(KislayPHPGateway, setDiscoveryBackend, arginfo_kislayphp_gateway_set_discovery_backend, ZEND_ACC_PUBLIC)
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
