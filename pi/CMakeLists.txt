cmake_minimum_required(VERSION 3.10)

project(offlinePiFS VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(nlohmann_json CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(server
    src/main.cpp
	src/server.cpp
    src/server_storage_manager.cpp
    security/src/crypto.cpp
    security/src/key_manager.cpp
)

target_include_directories(server PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/../shared/include
    ${PROJECT_SOURCE_DIR}/security/include
    ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(server PRIVATE
    nlohmann_json::nlohmann_json
    ${SODIUM_LIBRARIES}
)

