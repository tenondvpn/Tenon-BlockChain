cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ ip_src)
add_library(ip STATIC ${ip_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(ip PRIVATE common log4cpp xxhash)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(ip PRIVATE gcov)
    endif()
endif()

