cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ client_test_src)
add_executable(client_test ${client_test_src})

add_dependencies(client_test client)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(client_test PRIVATE client gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(client_test PRIVATE client gtest gtest_main gmock gmock_main)
endif()
