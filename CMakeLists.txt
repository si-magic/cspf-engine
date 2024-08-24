cmake_minimum_required(VERSION 3.10)

project(spf-engine VERSION 0.0.0)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

configure_file(
	src/spf-engine/config.h.in
	${CMAKE_BINARY_DIR}/spf-engine/config.h)

add_compile_options(-Wall -Wextra)

add_library(spf-engine
	${CMAKE_BINARY_DIR}/spf-engine/config.h
	src/ipaddress.cpp
	src/spf-engine/ipaddress.hpp
)

add_executable(spf-ipcalc src/spf-ipcalc.cpp)
target_link_libraries(spf-ipcalc spf-engine)
