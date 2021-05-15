cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ bft_test_src)
add_executable(bft_test ${bft_test_src})

add_dependencies(bft_test bft)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(bft_test PRIVATE bft ethash bz2 gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(bft_test PRIVATE bft gtest gtest_main gmock gmock_main)
endif()
