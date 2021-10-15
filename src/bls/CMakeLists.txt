cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ bls_src)
aux_source_directory(./proto proto_src)
add_library(bls STATIC ${bls_src} ${proto_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(bls PRIVATE network broadcast dht transport common security dkgbls ff gmp gmpxx  pbc uv protobuf log4cpp )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(bls PRIVATE gcov)
    endif()
endif()

