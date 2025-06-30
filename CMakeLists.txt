cmake_minimum_required(VERSION 3.20)

# Set toolchain before project() if using vcpkg
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain")
endif()

project(l2_middlewares)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Configure output directories to organize build artifacts
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)  # Executables
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)  # Shared libraries
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)  # Static libraries

# Ensure the output directories are created for all configurations
foreach(OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/out)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/out)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/out)
endforeach()

# Find required packages
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(src)

# ============================================================================
# Core Library (Shared between Login and Game servers)
# ============================================================================
add_library(L2Core STATIC
    # Core networking (base classes)
    src/core/network/base_client_connection.cpp
    src/core/network/base_connection_manager.cpp
    src/core/network/packet_buffer.cpp
    
    # Core packets
    src/core/packets/packet.cpp
    
    # Core encryption
    src/core/encryption/rsa_manager.cpp
    src/core/encryption/blowfish_openssl.cpp
    src/core/encryption/l2_checksum.cpp
    src/core/encryption/login_encryption.cpp
    src/core/encryption/game_client_encryption.cpp
    
    # Core utils
    src/core/utils/session_key.cpp
)

target_link_libraries(L2Core
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Windows-specific libraries for core
if(WIN32)
    target_link_libraries(L2Core ws2_32 wsock32)
endif()

# ============================================================================
# Login Server Executable
# ============================================================================
add_executable(L2LoginServer
    src/login/main.cpp
    src/login/server/login_server.cpp
    src/login/server/game_server_manager.cpp
    
    # Login-specific networking (inherits from core base classes)
    src/login/network/login_client_connection.cpp
    src/login/network/login_connection_manager.cpp
    
    # Login data structures
    src/login/data/server_data.cpp
    
    # Login packets
    src/login/packets/responses/init_packet.cpp
    src/login/packets/requests/auth_login_packet.cpp
    src/login/packets/requests/request_auth_gg.cpp
    src/login/packets/requests/request_server_list.cpp
    src/login/packets/requests/request_gs_login.cpp
    src/login/packets/responses/auth_gg_response.cpp
    src/login/packets/responses/login_ok_response.cpp
    src/login/packets/responses/server_list_response.cpp
    src/login/packets/responses/play_ok_response.cpp
    src/login/packets/packet_factory.cpp
)

target_link_libraries(L2LoginServer L2Core)

# ============================================================================
# Game Server Executable
# ============================================================================
add_executable(L2GameServer
    src/game/main.cpp
    src/game/server/game_server.cpp
    src/game/server/character_database_manager.cpp
    
    # Game-specific networking
    src/game/network/game_connection_manager.cpp
    src/game/network/game_client_connection.cpp
    
    # Game packet factory
    src/game/packets/packet_factory.cpp
    
    # Game request packets
    src/game/packets/requests/protocol_version_packet.cpp
    src/game/packets/requests/auth_login_packet.cpp
    src/game/packets/requests/new_char_request_packet.cpp
    src/game/packets/requests/create_char_request_packet.cpp
    src/game/packets/requests/logout_packet.cpp
    src/game/packets/requests/delete_char_packet.cpp
    src/game/packets/requests/restore_char_packet.cpp
    src/game/packets/requests/select_char_packet.cpp
    src/game/packets/requests/enter_world_packet.cpp
    src/game/packets/requests/no_op_packet.cpp
    
    # Game response packets
    src/game/packets/responses/ping_response.cpp
    src/game/packets/responses/version_check_response.cpp
    src/game/packets/responses/character_selection_info.cpp
    src/game/packets/responses/new_character_success.cpp
    src/game/packets/responses/character_create_success.cpp
)

target_link_libraries(L2GameServer L2Core)

# Set output names
set_target_properties(L2LoginServer PROPERTIES OUTPUT_NAME "l2_login_server")
set_target_properties(L2GameServer PROPERTIES OUTPUT_NAME "l2_game_server")
