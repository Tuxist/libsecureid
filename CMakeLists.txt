cmake_minimum_required(VERSION 3.0)
project(secureid C)
enable_testing ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-int-conversion")

set(LIBV "1")
set(Upstream_VERSION 1.0.0)

if(${DEBUG} MATCHES TRUE)
    add_definitions(-DDEBUG)
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/src
)

add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(doc)
