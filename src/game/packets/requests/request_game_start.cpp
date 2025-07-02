#include "request_game_start.hpp"
#include <stdexcept>

uint8_t RequestGameStart::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> RequestGameStart::getExPacketId() const
{
    return std::nullopt;
}

void RequestGameStart::read(ReadablePacketBuffer &buffer)
{
    try {
        // Read the character object ID (int32)
        character_object_id_ = buffer.readInt32();
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Failed to read RequestGameStart packet: " + std::string(e.what()));
    }
}

bool RequestGameStart::isValid() const
{
    // Character object ID should be positive (valid character slot)
    return character_object_id_ >= 0;
}