#include "delete_char_packet.hpp"

uint8_t DeleteCharPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> DeleteCharPacket::getExPacketId() const
{
    return std::nullopt;
}

void DeleteCharPacket::read(ReadablePacketBuffer &buffer)
{
    // TODO: Implement select char reading
}

bool DeleteCharPacket::isValid() const
{
    return true;
}