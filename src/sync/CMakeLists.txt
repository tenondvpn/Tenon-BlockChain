cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ sync_src)
aux_source_directory(./proto proto_src)
add_library(sync STATIC ${sync_src} ${proto_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(sync PRIVATE init bls dht transport common uv protobuf log4cpp )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(sync PRIVATE gcov)
    endif()
endif()

