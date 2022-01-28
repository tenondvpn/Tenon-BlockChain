cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ lvpn_src)
add_library(lvpn STATIC ${lvpn_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(lvpn PRIVATE client shadowsocks-libev bloom cork ipset sodium mbedtls event mbedx509 mbedcrypto pcre m pthread)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(lvpn PRIVATE gcov)
    endif()
endif()

