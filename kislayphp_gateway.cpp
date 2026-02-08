extern "C" {
#include "php.h"
#include "ext/standard/info.h"
#include "Zend/zend_exceptions.h"
}

#include "php_kislayphp_gateway.h"

#include <civetweb.h>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <strings.h>
#include <string>
#include <vector>

static zend_class_entry *kislayphp_gateway_ce;

struct kislayphp_gateway_route {
    std::string method;
    std::string path;
    std::string target;
    std::string host;
    int port;
    std::string base_path;
};

typedef struct _php_kislayphp_gateway_t {
    zend_object std;
    std::vector<kislayphp_gateway_route> routes;
    std::mutex lock;
    struct mg_context *ctx;
    bool running;
} php_kislayphp_gateway_t;

static zend_object_handlers kislayphp_gateway_handlers;

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
    new (&obj->lock) std::mutex();
    obj->ctx = nullptr;
    obj->running = false;
    obj->std.handlers = &kislayphp_gateway_handlers;
    return &obj->std;
}

static void kislayphp_gateway_free_obj(zend_object *object) {
    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(object);
    if (obj->ctx != nullptr) {
        mg_stop(obj->ctx);
        obj->ctx = nullptr;
    }
    obj->routes.~vector();
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

static bool kislayphp_parse_target(const std::string &target, kislayphp_gateway_route &route) {
    std::string value = target;
    const std::string prefix = "http://";
    if (value.rfind(prefix, 0) == 0) {
        value = value.substr(prefix.size());
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
    int port = 80;
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
    route.base_path = base_path;
    return true;
}

static void kislayphp_send_error(struct mg_connection *conn, int status, const char *message) {
    const char *status_text = "Error";
    if (status == 404) {
        status_text = "Not Found";
    } else if (status == 502) {
        status_text = "Bad Gateway";
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

static bool kislayphp_proxy_request(struct mg_connection *conn, const struct mg_request_info *info, const kislayphp_gateway_route &route) {
    char error_buf[256] = {0};
    struct mg_connection *target = mg_connect_client(route.host.c_str(), route.port, 0, error_buf, sizeof(error_buf));
    if (target == nullptr) {
        kislayphp_send_error(conn, 502, "Upstream connect failed");
        return false;
    }

    std::string path = info->local_uri ? info->local_uri : (info->request_uri ? info->request_uri : "/");
    std::string target_path = kislayphp_join_paths(route.base_path, path);
    if (info->query_string && *info->query_string) {
        target_path.append("?");
        target_path.append(info->query_string);
    }

    std::string method = info->request_method ? info->request_method : "GET";
    mg_printf(target, "%s %s HTTP/1.0\r\n", method.c_str(), target_path.c_str());
    mg_printf(target, "Host: %s:%d\r\n", route.host.c_str(), route.port);
    mg_printf(target, "Connection: close\r\n");

    bool has_content_length = false;
    for (int i = 0; i < info->num_headers; ++i) {
        const char *name = info->http_headers[i].name;
        const char *value = info->http_headers[i].value;
        if (name == nullptr || value == nullptr) {
            continue;
        }
        if (::strcasecmp(name, "Host") == 0 || ::strcasecmp(name, "Connection") == 0) {
            continue;
        }
        if (::strcasecmp(name, "Content-Length") == 0) {
            has_content_length = true;
        }
        mg_printf(target, "%s: %s\r\n", name, value);
    }

    if (!has_content_length) {
        mg_printf(target, "Content-Length: %lld\r\n", static_cast<long long>(info->content_length));
    }
    mg_printf(target, "\r\n");

    if (info->content_length > 0) {
        std::vector<char> body(static_cast<size_t>(info->content_length));
        size_t read_total = 0;
        while (read_total < body.size()) {
            int read_now = mg_read(conn, body.data() + read_total, body.size() - read_total);
            if (read_now <= 0) {
                break;
            }
            read_total += static_cast<size_t>(read_now);
        }
        if (read_total > 0) {
            mg_write(target, body.data(), read_total);
        }
    }

    char buffer[4096];
    int read_len = 0;
    while ((read_len = mg_read(target, buffer, sizeof(buffer))) > 0) {
        mg_write(conn, buffer, static_cast<size_t>(read_len));
    }

    mg_close_connection(target);
    return true;
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

    kislayphp_gateway_route match;
    bool found = false;
    {
        std::lock_guard<std::mutex> guard(gateway->lock);
        for (const auto &route : gateway->routes) {
            if (route.method == method && route.path == path) {
                match = route;
                found = true;
                break;
            }
        }
    }

    if (!found) {
        kislayphp_send_error(conn, 404, "Not Found");
        return 1;
    }

    kislayphp_proxy_request(conn, info, match);
    return 1;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_add, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, method, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, target, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kislayphp_gateway_listen, 0, 0, 2)
    ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
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
    if (!kislayphp_parse_target(route.target, route)) {
        zend_throw_exception(zend_ce_exception, "Invalid target (expected http://host:port)", 0);
        RETURN_FALSE;
    }
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
        add_assoc_string(&entry, "target", route.target.c_str());
        add_next_index_zval(return_value, &entry);
    }
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

    std::string listen_addr = std::string(host, host_len) + ":" + std::to_string(port);
    std::vector<const char *> options;
    options.push_back("listening_ports");
    options.push_back(listen_addr.c_str());
    options.push_back("num_threads");
    options.push_back("1");
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

PHP_METHOD(KislayPHPGateway, stop) {
    php_kislayphp_gateway_t *obj = php_kislayphp_gateway_from_obj(Z_OBJ_P(getThis()));
    obj->running = false;
    if (obj->ctx != nullptr) {
        mg_stop(obj->ctx);
        obj->ctx = nullptr;
    }
    RETURN_TRUE;
}

static const zend_function_entry kislayphp_gateway_methods[] = {
    PHP_ME(KislayPHPGateway, __construct, arginfo_kislayphp_gateway_void, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, addRoute, arginfo_kislayphp_gateway_add, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, routes, arginfo_kislayphp_gateway_void, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, listen, arginfo_kislayphp_gateway_listen, ZEND_ACC_PUBLIC)
    PHP_ME(KislayPHPGateway, stop, arginfo_kislayphp_gateway_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

PHP_MINIT_FUNCTION(kislayphp_gateway) {
    zend_class_entry ce;
    INIT_NS_CLASS_ENTRY(ce, "KislayPHP\\Gateway", "Gateway", kislayphp_gateway_methods);
    kislayphp_gateway_ce = zend_register_internal_class(&ce);
    kislayphp_gateway_ce->create_object = kislayphp_gateway_create_object;
    std::memcpy(&kislayphp_gateway_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    kislayphp_gateway_handlers.offset = XtOffsetOf(php_kislayphp_gateway_t, std);
    kislayphp_gateway_handlers.free_obj = kislayphp_gateway_free_obj;
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(kislayphp_gateway) {
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

#if defined(COMPILE_DL_KISLAYPHP_GATEWAY) || defined(ZEND_COMPILE_DL_EXT)
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif
extern "C" {
ZEND_GET_MODULE(kislayphp_gateway)
}
#endif
