cmake_minimum_required(VERSION 3.10)

project(offlinePiFS VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(sodium REQUIRED)

file(GLOB SOURCES "src/*.cpp")
add_executable(server ${SOURCES})

target_include_directories(server PRIVATE
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/../shared/include
)

target_link_libraries(server
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        sodium
)
