#include "logout_packet.hpp"

uint8_t LogoutPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> LogoutPacket::getExPacketId() const
{
    return std::nullopt;
}

void LogoutPacket::read(ReadablePacketBuffer &buffer)
{
    // TODO: Implement select char reading
}

bool LogoutPacket::isValid() const
{
    return true;
}