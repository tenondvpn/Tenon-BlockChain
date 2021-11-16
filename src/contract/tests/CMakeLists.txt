cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ contract_test_src)
add_executable(contract_test ${contract_test_src})

add_dependencies(contract_test contract)
target_link_libraries(contract_test PRIVATE client tvm init bft tvm block statistics vss network sync broadcast dht nat_traverse transport kcp bz2 db security json2pb ip limit tnet contract common protobuf uv uuid gtest gtest_main gmock gmock_main pthread dl)
