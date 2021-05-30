cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ tvm_src)
add_library(tvm STATIC ${tvm_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(tvm PRIVATE contract evmone hex evmc-loader evmc-instructions block common log4cpp )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(tvm PRIVATE gcov)
    endif()
endif()

