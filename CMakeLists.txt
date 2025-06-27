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

# Include directories
include_directories(src)
include_directories(third_party)

# Blowfish third-party library
add_library(blowfish STATIC
    third_party/blowfish/blowfish.cc
    third_party/blowfish/blowfish2.cc
)

target_include_directories(blowfish PUBLIC third_party)

# Main executable
add_executable(l2_middlewares
    src/main.cpp
)

target_link_libraries(l2_middlewares
    Boost::system
    blowfish
)

# Windows-specific libraries
if(WIN32)
    target_link_libraries(l2_middlewares ws2_32 wsock32)
endif()
