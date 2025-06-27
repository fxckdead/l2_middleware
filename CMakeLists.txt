cmake_minimum_required(VERSION 3.20)

# Set toolchain before project() if using vcpkg
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain")
endif()

project(l2_middlewares)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(src)

# Main executable
add_executable(l2_middlewares
    src/main.cpp
    src/rsa_manager.cpp
    src/blowfish_openssl.cpp
    src/l2_checksum.cpp
    src/login_encryption.cpp
    src/session_key.cpp
)

target_link_libraries(l2_middlewares
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Windows-specific libraries
if(WIN32)
    target_link_libraries(l2_middlewares ws2_32 wsock32)
endif()
