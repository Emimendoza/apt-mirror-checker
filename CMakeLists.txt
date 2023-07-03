cmake_minimum_required(VERSION 3.25)
project(Verify CXX)

set(CMAKE_CXX_STANDARD 23)

# Find libcurl package
find_package(CURL REQUIRED)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Add the libcurl and OpenSSL include directories
include_directories(${CURL_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

# Optimize release
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=x86-64 -mtune=generic")

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")
endif()

# Add the executable and link against libcurl and OpenSSL
add_executable(Verify main.cpp)
target_link_libraries(Verify PRIVATE ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES})
