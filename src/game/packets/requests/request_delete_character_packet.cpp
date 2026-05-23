#include "request_delete_character_packet.hpp"

uint8_t RequestCharacterDeletePacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> RequestCharacterDeletePacket::getExPacketId() const
{
    return std::nullopt;
}

void RequestCharacterDeletePacket::read(ReadablePacketBuffer &buffer)
{
    // TODO: Implement select char reading
}

bool RequestCharacterDeletePacket::isValid() const
{
    return true;
}