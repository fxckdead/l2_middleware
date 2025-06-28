#pragma once

#include "../../core/packets/packet.hpp"
#include "../../core/network/packet_buffer.hpp"
#include "requests/auth_login_packet.hpp"
#include "responses/init_packet.hpp"
#include "requests/request_auth_gg.hpp"
#include "responses/auth_gg_response.hpp"
#include "responses/login_ok_response.hpp"
#include "../../core/encryption/rsa_manager.hpp"
#include <memory>
#include <vector>
#include <cstdint>

// Enumeration of client packet types (matches Rust ClientPackets enum)
enum class ClientPacketType : uint8_t
{
    RequestAuthLogin = 0x00,
    RequestGSLogin = 0x02,
    RequestServerList = 0x05,
    RequestAuthGG = 0x07
};

// Packet Factory - matches Rust cp_factory.rs pattern
// Centralizes packet creation and handles complex RSA decryption logic
class PacketFactory
{
public:
    // Create packets from raw client data (matches build_client_message_packet)
    static std::unique_ptr<ReadablePacket> createFromClientData(
        const std::vector<uint8_t> &rawData,
        const ScrambledRSAKeyPair &rsaPair);

    // Create specific outgoing packets
    static std::unique_ptr<InitPacket> createInitPacket(
        int32_t sessionId,
        const ScrambledRSAKeyPair &rsaPair,
        const std::vector<uint8_t> &blowfishKey);

    static std::unique_ptr<AuthGGResponse> createAuthGGResponse(int32_t sessionId);

    static std::unique_ptr<LoginOkResponse> createLoginOkResponse(const SessionKey &sessionKey);

    // Test function


private:
    // Handle RSA decryption for login packets (matches Rust logic exactly)
    static std::vector<uint8_t> decryptLoginData(
        const std::vector<uint8_t> &encryptedData,
        const ScrambledRSAKeyPair &rsaPair);

    // Extract opcode from raw packet data
    static uint8_t extractOpcode(const std::vector<uint8_t> &data);

    // Validate packet data before processing
    static bool isValidPacketData(const std::vector<uint8_t> &data);

    // Create specific packet types
    static std::unique_ptr<AuthLoginPacket> createAuthLoginPacket(
        const std::vector<uint8_t> &rawData,
        const ScrambledRSAKeyPair &rsaPair);

    // Placeholder for future packet types
    static std::unique_ptr<ReadablePacket> createAuthGGPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createGSLoginPacket(const std::vector<uint8_t> &rawData);
    static std::unique_ptr<ReadablePacket> createServerListPacket(const std::vector<uint8_t> &rawData);
};