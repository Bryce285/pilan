cmake_minimum_required(VERSION 3.10)
project(offlinePiFS VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(nlohmann_json CONFIG REQUIRED)

file(GLOB SOURCES "src/*cpp")
add_executable(client ${SOURCES})

target_include_directories(client PRIVATE
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/../shared/include	
)

target_link_libraries(client
	PRIVATE
		nlohmann_json::nlohmann_json
)
