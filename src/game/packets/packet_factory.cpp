// src/game/packets/packet_factory.cpp
#include "packet_factory.hpp"
#include "requests/no_op_packet.hpp"
#include "requests/create_char_request_packet.hpp"
#include <iostream>
#include <iomanip>
#include <stdexcept>

// Create packets from raw client data (matches login pattern exactly)
std::unique_ptr<ReadablePacket> GamePacketFactory::createFromClientData(
    const std::vector<uint8_t> &rawData)
{
    if (!isValidPacketData(rawData))
    {
        throw PacketException("Not enough data to build packet");
    }

    uint8_t opcode = extractOpcode(rawData);

    // ⭐ ADD THIS DEBUG LOGGING ⭐
    std::cout << "GamePacketFactory: Creating packet with opcode 0x"
              << std::hex << static_cast<int>(opcode) << std::dec << std::endl;

    // Remove opcode from data (matches login: data.split_to(1))
    std::vector<uint8_t> packetData(rawData.begin() + 1, rawData.end());

    // Check if this is an extended packet (0xD0)
    if (opcode == static_cast<uint8_t>(GameClientPacketType::ExtendedPacket))
    {
        return createExtendedPacket(packetData);
    }

    switch (static_cast<GameClientPacketType>(opcode))
    {
    case GameClientPacketType::SendProtocolVersion:
        // 0x00 - Client announcing protocol version (Interlude Update 3)
        std::cout << "Handling SendProtocolVersion packet (0x00)" << std::endl;
        return createProtocolVersionPacket(packetData);

    case GameClientPacketType::MoveBackwardToLocation:
        // 0x01 - Movement packet
        std::cout << "Handling MoveBackwardToLocation packet (0x01) as NoOp" << std::endl;
        return createNoOpPacket(packetData);

    case GameClientPacketType::Say:
        // 0x02 - Chat packet
        std::cout << "Handling Say packet (0x02) as NoOp" << std::endl;
        return createNoOpPacket(packetData);

    case GameClientPacketType::RequestEnterWorld:
        // 0x03 - Enter world request
        std::cout << "Handling RequestEnterWorld packet (0x03)" << std::endl;
        return createEnterWorldPacket(packetData);

    case GameClientPacketType::Action:
        // 0x04 - Action packet (attack, pickup, etc)
        std::cout << "Handling Action packet (0x04) as NoOp" << std::endl;
        return createNoOpPacket(packetData);

    case GameClientPacketType::RequestLogin:
        // 0x08 - Login authentication
        std::cout << "Handling RequestLogin packet (0x08)" << std::endl;
        return createAuthLoginPacket(packetData);

    case GameClientPacketType::SendLogOut:
        // 0x09 - Logout request
        std::cout << "Handling SendLogOut packet (0x09) as NoOp" << std::endl;
        return createNoOpPacket(packetData);

    case GameClientPacketType::RequestAttack:
        // 0x0A - Attack request
        std::cout << "Handling RequestAttack packet (0x0A) as NoOp" << std::endl;
        return createNoOpPacket(packetData);

    case GameClientPacketType::RequestCharacterCreate:
        // 0x0B - Character creation
        return createCreateCharRequestPacket(packetData);

    case GameClientPacketType::RequestCharacterDelete:
        // 0x0C - Character deletion
        return createDeleteCharPacket(packetData);

    case GameClientPacketType::RequestGameStart:
        // 0x0D - Game start (character selection)
        return createSelectCharPacket(packetData);

    case GameClientPacketType::RequestNewCharacter:
        // 0x0E - New character info request
        return createNewCharRequestPacket(packetData);

    default:
        std::cout << "Unknown Game Client packet ID: 0x" << std::hex << static_cast<int>(opcode) << std::dec << std::endl;
        return createNoOpPacket(packetData);
    }
}

// Extract opcode from raw packet data (matches login pattern)
uint8_t GamePacketFactory::extractOpcode(const std::vector<uint8_t> &data)
{
    return data[0];
}

// Validate packet data before processing (matches login pattern)
bool GamePacketFactory::isValidPacketData(const std::vector<uint8_t> &data)
{
    return !data.empty();
}

// Create specific standard packet types (matches login pattern)
std::unique_ptr<ReadablePacket> GamePacketFactory::createNoOpPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<NoOpPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create NoOp packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createProtocolVersionPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<ProtocolVersionPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create ProtocolVersion packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createAuthLoginPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<AuthLoginPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create AuthLogin packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createNewCharRequestPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<NewCharRequestPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create NewCharRequest packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createCreateCharRequestPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<CreateCharRequestPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create CreateCharRequest packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createLogoutPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<LogoutPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create Logout packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createDeleteCharPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<DeleteCharPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create DeleteChar packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createRestoreCharPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<RestoreCharPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create RestoreChar packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createSelectCharPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<SelectCharPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create SelectChar packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createEnterWorldPacket(const std::vector<uint8_t> &rawData)
{
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<EnterWorldPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create EnterWorld packet: " + std::string(e.what()));
    }
}

// Create extended packet types (NEW - game server complexity)
std::unique_ptr<ReadablePacket> GamePacketFactory::createExtendedPacket(const std::vector<uint8_t> &rawData)
{
    if (rawData.size() < 2)
    {
        throw PacketException("Empty extended packet - not enough data for sub-opcode");
    }

    // Read 16-bit sub-opcode (little-endian)
    uint16_t sub_opcode = static_cast<uint16_t>(rawData[0]) | (static_cast<uint16_t>(rawData[1]) << 8);

    // Remove sub-opcode from data
    std::vector<uint8_t> extPacketData(rawData.begin() + 2, rawData.end());

    switch (static_cast<ExtendedGamePacketType>(sub_opcode))
    {
    case ExtendedGamePacketType::GoLobby:
        return createGoLobbyPacket(extPacketData);

    case ExtendedGamePacketType::CheckCharName:
        return createCheckCharNamePacket(extPacketData);

    case ExtendedGamePacketType::SendClientIni:
        return createSendClientIniPacket(extPacketData);

    case ExtendedGamePacketType::RequestUserBanInfo:
        return createRequestUserBanInfoPacket(extPacketData);

    default:
        throw PacketException("Unknown extended game packet sub-opcode: 0x" +
                              std::to_string(sub_opcode));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createGoLobbyPacket(const std::vector<uint8_t> &rawData)
{
    // TODO: Create GoLobbyPacket class - using NoOpPacket for now
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<NoOpPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create GoLobby packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createCheckCharNamePacket(const std::vector<uint8_t> &rawData)
{
    // TODO: Create CheckCharNamePacket class - using NoOpPacket for now
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<NoOpPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create CheckCharName packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createSendClientIniPacket(const std::vector<uint8_t> &rawData)
{
    // TODO: Create SendClientIniPacket class - using NoOpPacket for now
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<NoOpPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create SendClientIni packet: " + std::string(e.what()));
    }
}

std::unique_ptr<ReadablePacket> GamePacketFactory::createRequestUserBanInfoPacket(const std::vector<uint8_t> &rawData)
{
    // TODO: Create RequestUserBanInfoPacket class - using NoOpPacket for now
    try
    {
        ReadablePacketBuffer buffer(rawData);
        auto packet = std::make_unique<NoOpPacket>();
        packet->read(buffer);
        return packet;
    }
    catch (const std::exception &e)
    {
        throw PacketException("Failed to create RequestUserBanInfo packet: " + std::string(e.what()));
    }
}