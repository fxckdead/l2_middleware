#include "restore_char_packet.hpp"

uint8_t RestoreCharPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> RestoreCharPacket::getExPacketId() const
{
    return std::nullopt;
}

void RestoreCharPacket::read(ReadablePacketBuffer &buffer)
{
    // TODO: Implement select char reading
}

bool RestoreCharPacket::isValid() const
{
    return true;
}