find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)

if (GLIB_PKG_FOUND)
    message(Found glib-2.0)
    include_directories(${GLIB_PKG_INCLUDE_DIRS})
endif ()

aux_source_directory(. DIR_SRCS)
add_library(radix_fib_lib ${DIR_SRCS} sid.h)
target_link_libraries(radix_fib_lib glib-2.0)