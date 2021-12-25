cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ db_src)
add_library(db STATIC ${db_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(db PRIVATE dbsvr leveldb log4cpp snappy z bz2 zstd lz4)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(db PRIVATE gcov)
    endif()
endif()

