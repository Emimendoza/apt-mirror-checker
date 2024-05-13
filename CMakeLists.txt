cmake_minimum_required(VERSION 3.20)
project(apt-mirror-tools CXX)

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

# Check if the <format> header is available
include(CheckIncludeFileCXX)
check_include_file_cxx(format HAS_CXX_FORMAT)

if (NOT HAS_CXX_FORMAT)
    message(STATUS "The <format> header is not available, cloning fmt from GitHub...")

    # Set the directory where you want to clone fmt
    set(FMT_INSTALL_DIR "${CMAKE_BINARY_DIR}/fmt")

    # Clone fmt from GitHub
    if (NOT EXISTS "${FMT_INSTALL_DIR}/CMakeLists.txt")
        message(STATUS "Cloning fmt from GitHub...")

        # Remove the fmt directory if it exists
        if (EXISTS "${FMT_INSTALL_DIR}")
            file(REMOVE_RECURSE "${FMT_INSTALL_DIR}")
        endif ()

        # Clone fmt from GitHub
        execute_process(
                COMMAND git clone https://github.com/fmtlib/fmt.git ${FMT_INSTALL_DIR}
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                RESULT_VARIABLE GIT_RESULT
        )

        if (NOT GIT_RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to clone fmt from GitHub")
        endif ()
    else ()
        message(STATUS "Using existing fmt repository.")
    endif ()
    # Add fmt as a subdirectory and build it
    add_subdirectory(${FMT_INSTALL_DIR} fmt_build)

else ()
    message(STATUS "Found <format> header. No need to clone fmt.")
endif ()

# Find libcurl package
find_package(CURL REQUIRED)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Find lzma
find_package(LibLZMA REQUIRED)

# Optimize release

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto=auto -O3 -s -march=x86-64 -mtune=generic")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")
endif()

# Add the executable and link against libcurl and OpenSSL
add_executable(apt-mirror-tools # main.cpp
        src/apt_mirror_tools.cpp
        src/apt_mirror_tools.h
        src/print.h
        src/main.cpp
)
# Old implementation
add_executable(apt-mirror-checker
        ./main.cpp
)
if(NOT HAS_CXX_FORMAT)
    target_link_libraries(apt-mirror-tools ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES} ${LIBLZMA_LIBRARIES} fmt)
    target_link_libraries(apt-mirror-checker ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES} ${LIBLZMA_LIBRARIES} fmt)
else ()
    target_link_libraries(apt-mirror-tools ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES} ${LIBLZMA_LIBRARIES} )
    target_link_libraries(apt-mirror-checker ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES} ${LIBLZMA_LIBRARIES})
endif()