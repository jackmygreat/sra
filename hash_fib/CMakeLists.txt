find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)

if (GLIB_PKG_FOUND)
    message(Found glib-2.0)
    include_directories(${GLIB_PKG_INCLUDE_DIRS})
endif ()

aux_source_directory(. DIR_SRCS)
add_library(hash_fib_lib ${DIR_SRCS})
target_link_libraries(hash_fib_lib glib-2.0)