cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

add_executable(tcp_demo tcp.cc)

add_dependencies(tcp_demo transport tnet common protobuf pthread dl)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(tcp_demo PRIVATE transport common tnet pthread dl)
endif()
