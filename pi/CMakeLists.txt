cmake_minimum_required(VERSION 3.10)

project(offlinePiFS VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(BUILD_SHARED_LIBS OFF)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(server
    src/main.cpp
	src/paths.cpp
	src/server.cpp
    src/server_storage_manager.cpp
	src/logger.cpp
    security/src/crypto.cpp
    security/src/key_manager.cpp
)

target_compile_options(server PRIVATE
    -Wvla
    -fstack-protector-strong
	-Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
)

target_link_options(server PRIVATE -static)

target_include_directories(server PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/../shared/include
    ${PROJECT_SOURCE_DIR}/security/include
    ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(server PRIVATE
    ${SODIUM_LIBRARIES}
)

