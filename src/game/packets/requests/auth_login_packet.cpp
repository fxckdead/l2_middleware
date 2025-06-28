#include "auth_login_packet.hpp"

uint8_t AuthLoginPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> AuthLoginPacket::getExPacketId() const
{
    return std::nullopt;
}

void AuthLoginPacket::read(ReadablePacketBuffer &buffer)
{
    // TODO: Implement select char reading
}

bool AuthLoginPacket::isValid() const
{
    return true;
}