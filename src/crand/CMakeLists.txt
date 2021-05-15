cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ crand_src)
add_library(crand STATIC ${crand_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(crand PRIVATE log4cpp snappy z bz2 zstd lz4)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(crand PRIVATE gcov)
    endif()
endif()

