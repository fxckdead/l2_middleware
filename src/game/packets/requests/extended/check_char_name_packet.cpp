#include "check_char_name_packet.hpp"

uint8_t CheckCharNamePacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> CheckCharNamePacket::getExPacketId() const
{
    return std::nullopt;
}

void CheckCharNamePacket::read(ReadablePacketBuffer &buffer)
{
    // TODO: Implement select char reading
}

bool CheckCharNamePacket::isValid() const
{
    return true;
}