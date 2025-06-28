#include "send_client_ini_packet.hpp"

uint8_t SendClientIniPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> SendClientIniPacket::getExPacketId() const
{
    return std::nullopt;
}

void SendClientIniPacket::read(ReadablePacketBuffer &buffer)
{
    // TODO: Implement select char reading
}

bool SendClientIniPacket::isValid() const
{
    return true;
}