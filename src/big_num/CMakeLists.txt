cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ big_num_src)
add_library(big_num STATIC ${big_num_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(big_num PRIVATE ff gmp log4cpp)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(big_num PRIVATE gcov)
    endif()
endif()

