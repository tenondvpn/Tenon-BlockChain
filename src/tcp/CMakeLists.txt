cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ tcp_src)
add_library(tcp STATIC ${tcp_src})

target_link_libraries(tcp PRIVATE common evhtp event event_openssl ssl crypto log4cpp pthread dl)
