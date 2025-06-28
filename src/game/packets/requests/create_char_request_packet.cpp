#include "create_char_request_packet.hpp"

uint8_t CreateCharRequestPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> CreateCharRequestPacket::getExPacketId() const
{
    return std::nullopt;
}

void CreateCharRequestPacket::read(ReadablePacketBuffer &buffer)
{
    // TODO: Implement select char reading
}

bool CreateCharRequestPacket::isValid() const
{
    return true;
}