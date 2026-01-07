cmake_minimum_required(VERSION 3.10)
project(offlinePiFS VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(nlohmann_json CONFIG REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/include)

file(GLOB SOURCES "src/*cpp")
add_executable(client ${SOURCES})

target_link_libraries(server
	PRIVATE
		nlohmann_json::nlohmann_json
)
