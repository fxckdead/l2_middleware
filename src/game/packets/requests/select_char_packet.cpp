#include "select_char_packet.hpp"

uint8_t SelectCharPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> SelectCharPacket::getExPacketId() const
{
    return std::nullopt;
}

void SelectCharPacket::read(ReadablePacketBuffer &buffer)
{
    // TODO: Implement select char reading
}

bool SelectCharPacket::isValid() const
{
    return true;
}