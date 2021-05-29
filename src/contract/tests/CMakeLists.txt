cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ contract_test_src)
add_executable(contract_test ${contract_test_src})

add_dependencies(contract_test contract)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(contract_test PRIVATE contract common gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(contract_test PRIVATE contract gtest gtest_main gmock gmock_main)
endif()
