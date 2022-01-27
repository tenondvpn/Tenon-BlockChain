cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ tcp_test_src)
add_executable(tcp_test ${tcp_test_src})

add_dependencies(tcp_test tcp)
target_link_libraries(tcp_test PRIVATE tcp event boost_system gtest gtest_main gmock gmock_main pthread dl)
