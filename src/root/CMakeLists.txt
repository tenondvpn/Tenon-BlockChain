cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ root_src)
add_library(root STATIC ${root_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(root PRIVATE init vss bft vss network dht transport security block db common uv protobuf log4cpp pthread )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(root PRIVATE gcov)
    endif()
endif()

