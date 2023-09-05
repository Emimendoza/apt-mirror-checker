cmake_minimum_required(VERSION 3.20)
project(apt-mirror-checker CXX)

# Check if the compiler supports C++23
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-std=c++23" COMPILER_SUPPORTS_CXX23)
check_cxx_compiler_flag("-std=c++20" COMPILER_SUPPORTS_CXX20)

if(COMPILER_SUPPORTS_CXX23)
    message(STATUS "Compiler supports C++23.")
    set(CMAKE_CXX_STANDARD 23)
elseif(COMPILER_SUPPORTS_CXX20)
    message(STATUS "Compiler supports C++20, using C++20.")
    set(CMAKE_CXX_STANDARD 20)
else()
    message(FATAL_ERROR "Compiler does not support C++20 or higher.")
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


# Find libcurl package
find_package(CURL REQUIRED)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Add the libcurl and OpenSSL include directories
include_directories(${CURL_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

# Optimize release

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto=auto -O3 -s -march=x86-64 -mtune=generic")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")
endif()

# Add the executable and link against libcurl and OpenSSL
add_executable(apt-mirror-checker main.cpp)
target_link_libraries(apt-mirror-checker PRIVATE ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES})