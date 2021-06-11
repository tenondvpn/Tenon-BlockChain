cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ timeblock_src)
add_library(timeblock STATIC ${timeblock_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(timeblock PRIVATE election common log4cpp snappy z bz2 zstd lz4)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(timeblock PRIVATE gcov)
    endif()
endif()

