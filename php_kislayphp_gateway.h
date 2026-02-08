#ifndef PHP_KISLAYPHP_GATEWAY_H
#define PHP_KISLAYPHP_GATEWAY_H

extern "C" {
#include "php.h"
}

#define PHP_KISLAYPHP_GATEWAY_VERSION "0.1"
#define PHP_KISLAYPHP_GATEWAY_EXTNAME "kislayphp_gateway"

extern zend_module_entry kislayphp_gateway_module_entry;
#define phpext_kislayphp_gateway_ptr &kislayphp_gateway_module_entry

#endif
