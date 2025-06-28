#include "packet_factory.hpp"
#include <iostream>
#include <iomanip>
#include <stdexcept>

// Create packets from raw client data (matches build_client_message_packet)
std::unique_ptr<ReadablePacket> PacketFactory::createFromClientData(
    const std::vector<uint8_t> &rawData,
    const ScrambledRSAKeyPair &rsaPair)
{
    if (!isValidPacketData(rawData))
    {
        throw PacketException("Not enough data to build packet");
    }

    uint8_t opcode = extractOpcode(rawData);

    // Remove opcode from data (matches Rust: data.split_to(1))
    std::vector<uint8_t> packetData(rawData.begin() + 1, rawData.end());

    switch (static_cast<ClientPacketType>(opcode))
    {
    case ClientPacketType::RequestAuthLogin:
        return createAuthLoginPacket(packetData, rsaPair);

    case ClientPacketType::RequestAuthGG:
        return createAuthGGPacket(packetData);

    case ClientPacketType::RequestGSLogin:
        return createGSLoginPacket(packetData);

    case ClientPacketType::RequestServerList:
        return createServerListPacket(packetData);

    default:
        throw PacketException("Unknown Client packet ID: 0x" +
                              std::to_string(static_cast<int>(opcode)));
    }
}

// Create specific outgoing packets
std::unique_ptr<InitPacket> PacketFactory::createInitPacket(
    int32_t sessionId,
    const ScrambledRSAKeyPair &rsaPair,
    const std::vector<uint8_t> &blowfishKey)
{
    return std::make_unique<InitPacket>(sessionId, rsaPair, blowfishKey);
}

std::unique_ptr<AuthGGResponse> PacketFactory::createAuthGGResponse(int32_t sessionId)
{
    return std::make_unique<AuthGGResponse>(sessionId);
}

std::unique_ptr<LoginOkResponse> PacketFactory::createLoginOkResponse(const SessionKey &sessionKey)
{
    return std::make_unique<LoginOkResponse>(sessionKey);
}

std::unique_ptr<ServerListResponse> PacketFactory::createServerListResponse(const std::vector<ServerData>& servers)
{
    return std::make_unique<ServerListResponse>(servers);
}

std::unique_ptr<ServerListResponse> PacketFactory::createServerListResponseWithCharInfo(
    const std::vector<ServerData>& servers,
    const std::unordered_map<uint8_t, GSCharsInfo>& charsOnServer)
{
    return std::make_unique<ServerListResponse>(servers, 0, charsOnServer);
}

std::unique_ptr<PlayOkResponse> PacketFactory::createPlayOkResponse(const SessionKey &sessionKey)
{
    return std::make_unique<PlayOkResponse>(sessionKey);
}

// Handle RSA decryption for login packets (matches Rust logic exactly)
std::vector<uint8_t> PacketFactory::decryptLoginData(
    const std::vector<uint8_t> &encryptedData,
    const ScrambledRSAKeyPair &rsaPair)
{
    if (encryptedData.size() < 128)
    {
        throw PacketException("Insufficient data for RSA decryption");
    }

    // Extract first 128 bytes (matches Rust: data.split_at(128))
    std::vector<uint8_t> raw1(encryptedData.begin(), encryptedData.begin() + 128);

    // Decrypt first block using raw RSA decryption (no padding removal)
    std::vector<uint8_t> decrypted = RSAManager::rsaDecryptRaw(raw1, rsaPair.getPrivateKey());

    bool isNewAuth = false;

    // Check if we have enough data for new auth format (256+ bytes total)
    if (encryptedData.size() >= 256)
    {
        // Extract second 128 bytes (matches Rust: rest.split_at(128))
        std::vector<uint8_t> raw2(encryptedData.begin() + 128, encryptedData.begin() + 256);

        // Decrypt second block
        std::vector<uint8_t> decrypted2 = RSAManager::rsaDecryptRaw(raw2, rsaPair.getPrivateKey());

        // Append second block to first (matches Rust: decrypted.put_slice(&decr_raw2))
        decrypted.insert(decrypted.end(), decrypted2.begin(), decrypted2.end());
        isNewAuth = true;
    }

    // Add new auth flag (matches Rust: decrypted.put_u8(u8::from(is_new_auth)))
    decrypted.push_back(isNewAuth ? 1 : 0);

    return decrypted;
}

// Extract opcode from raw packet data
uint8_t PacketFactory::extractOpcode(const std::vector<uint8_t> &data)
{
    return data[0];
}

// Validate packet data before processing
bool PacketFactory::isValidPacketData(const std::vector<uint8_t> &data)
{
    return !data.empty();
}

// Create AuthLogin packet with RSA decryption
std::unique_ptr<AuthLoginPacket> PacketFactory::createAuthLoginPacket(
    const std::vector<uint8_t> &rawData,
    const ScrambledRSAKeyPair &rsaPair)
{
    try
    {
        // Decrypt the RSA-encrypted login data (matches Rust logic exactly)
        std::vector<uint8_t> decryptedData = decryptLoginData(rawData, rsaPair);

        // Create AuthLoginPacket from decrypted data and return as unique_ptr
        AuthLoginPacket tempPacket = AuthLoginPacket::fromRsaDecryptedData(decryptedData);

        return std::make_unique<AuthLoginPacket>(tempPacket.getUsername(), tempPacket.getPassword());
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create AuthLogin packet: " + std::string(e.what()));
    }
}

// Create AuthGG packet (no decryption needed, just session ID validation)
std::unique_ptr<ReadablePacket> PacketFactory::createAuthGGPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        // Create RequestAuthGG from raw data (no RSA decryption needed)
        RequestAuthGG tempPacket = RequestAuthGG::fromRawData(rawData);

        return std::make_unique<RequestAuthGG>(tempPacket.getSessionId());
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create AuthGG packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> PacketFactory::createGSLoginPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        // Create a ReadablePacketBuffer from the raw data
        ReadablePacketBuffer buffer(rawData);
        
        // Create RequestGSLogin and read the data (matches Rust read() implementation)
        auto packet = std::make_unique<RequestGSLogin>();
        packet->read(buffer);
        
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create RequestGSLogin packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> PacketFactory::createServerListPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        // Create a ReadablePacketBuffer from the raw data
        ReadablePacketBuffer buffer(rawData);
        
        // Create RequestServerList and read the data
        auto packet = std::make_unique<RequestServerList>();
        packet->read(buffer);
        
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create RequestServerList packet: " + std::string(e.what()));
    }
}
