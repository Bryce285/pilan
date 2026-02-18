cmake_minimum_required(VERSION 3.10)
project(offlinePiFS VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_definitions(LOCALTEST=1)

find_package(nlohmann_json CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(client
	src/main.cpp
	src/client.cpp
	src/client_storage_manager.cpp
	security/src/crypto.cpp	
)

target_compile_options(client PRIVATE
	-Wvla
	-fstack-protector-strong
	-Wall
	-Wextra
	-Wpedantic
	-Wshadow
	-Wconversion
)

target_include_directories(client PRIVATE
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/../shared/include
	${PROJECT_SOURCE_DIR}/security/include
	${SODIUM_INCLUDE_DIRS}	
)

target_link_libraries(client
	PRIVATE
		nlohmann_json::nlohmann_json
		${SODIUM_LIBRARIES}
)
