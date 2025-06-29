// src/game/packets/packet_factory.hpp
#pragma once

#include "../../core/packets/packet.hpp"
#include "../../core/network/packet_buffer.hpp"
#include "requests/protocol_version_packet.hpp"
#include "requests/auth_login_packet.hpp"
#include "requests/new_char_request_packet.hpp"
#include "requests/create_char_request_packet.hpp"
#include "requests/logout_packet.hpp"
#include "requests/delete_char_packet.hpp"
#include "requests/restore_char_packet.hpp"
#include "requests/select_char_packet.hpp"
#include "requests/enter_world_packet.hpp"
#include "requests/no_op_packet.hpp"
#include "requests/extended/go_lobby_packet.hpp"
#include "requests/extended/check_char_name_packet.hpp"
#include "requests/extended/send_client_ini_packet.hpp"
#include "requests/extended/request_user_ban_info_packet.hpp"

#include <memory>
#include <vector>
#include <cstdint>

// Enumeration of game client packet types
// Interlude Update 3 Game Client Packet Opcodes
enum class GameClientPacketType : uint8_t
{
    SendProtocolVersion = 0x00,     // Client protocol version announcement
    MoveBackwardToLocation = 0x01,  // Movement packet
    Say = 0x02,                     // Chat packet
    RequestEnterWorld = 0x03,       // Enter world request
    Action = 0x04,                  // Action packet (attack, pickup, etc)
    RequestLogin = 0x08,            // Login authentication  
    SendLogOut = 0x09,              // Logout request
    RequestAttack = 0x0A,           // Attack request
    RequestCharacterCreate = 0x0B,  // Character creation
    RequestCharacterDelete = 0x0C,  // Character deletion
    RequestGameStart = 0x0D,        // Game start (character selection)
    RequestNewCharacter = 0x0E,     // New character info request
    
    // Extended packets (0xD0 + sub-opcode)
    ExtendedPacket = 0xD0
};

// Extended packet sub-opcodes (16-bit values after 0xD0)
enum class ExtendedGamePacketType : uint16_t
{
    GoLobby = 0x001B,
    CheckCharName = 0x008F,
    SendClientIni = 0x00CD,
    RequestUserBanInfo = 0x00CF
};

// Game Packet Factory - matches Login PacketFactory pattern
// Handles game server packet creation (5x more complex than login server)
class GamePacketFactory
{
public:
    // Create packets from raw client data (matches login pattern)
    static std::unique_ptr<ReadablePacket> createFromClientData(
        const std::vector<uint8_t> &rawData);

private:
    // Extract opcode from raw packet data (matches login pattern)
    static uint8_t extractOpcode(const std::vector<uint8_t> &data);

    // Validate packet data before processing (matches login pattern)
    static bool isValidPacketData(const std::vector<uint8_t> &data);

    static std::unique_ptr<ReadablePacket> createNoOpPacket(const std::vector<uint8_t> &rawData);

    // Create specific standard packet types (matches login pattern)
    static std::unique_ptr<ReadablePacket> createProtocolVersionPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createAuthLoginPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createNewCharRequestPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createCreateCharRequestPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createLogoutPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createDeleteCharPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createRestoreCharPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createSelectCharPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createEnterWorldPacket(const std::vector<uint8_t> &rawData);

    // Create extended packet types (NEW - game server complexity)
    static std::unique_ptr<ReadablePacket> createExtendedPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createGoLobbyPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createCheckCharNamePacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createSendClientIniPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createRequestUserBanInfoPacket(const std::vector<uint8_t> &rawData);
};