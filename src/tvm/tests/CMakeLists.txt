cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ tvm_test_src)
add_executable(tvm_test ${tvm_test_src})

add_dependencies(tvm_test tvm)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(tvm_test PRIVATE tvm init vss bft vss network dht transport security block db common uv protobuf log4cpp pthread gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(tvm_test PRIVATE tvm gtest gtest_main gmock gmock_main)
endif()
