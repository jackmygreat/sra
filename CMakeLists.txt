cmake_minimum_required(VERSION 3.16)
project(xsk_srv6 C)
set(CMAKE_C_STANDARD 99)
add_subdirectory(common)
#add_subdirectory(hash_fib)
add_subdirectory(radix_fib)


find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)

if (GLIB_PKG_FOUND)
    message(Found glib-2.0)
    include_directories(${GLIB_PKG_INCLUDE_DIRS})
endif ()

add_executable(xsk_srv6 main.c)
#target_link_libraries(xsk_srv6 common_lib hash_fib_lib bpf pthread)
target_link_libraries(xsk_srv6 common_lib radix_fib_lib bpf pthread)
