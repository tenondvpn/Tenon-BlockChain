cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ dbsvr_src)
aux_source_directory(./util util_src)
aux_source_directory(./ssdb ssdb_src)
aux_source_directory(./net net_src)
add_library(dbsvr STATIC ${util_src} ${ssdb_src} ${net_src} ${dbsvr_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(dbsvr PRIVATE leveldb log4cpp)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(dbsvr PRIVATE leveldb gcov)
    endif()
endif()

