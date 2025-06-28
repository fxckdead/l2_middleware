#include "request_user_ban_info_packet.hpp"

uint8_t RequestUserBanInfoPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> RequestUserBanInfoPacket::getExPacketId() const
{
    return std::nullopt;
}

void RequestUserBanInfoPacket::read(ReadablePacketBuffer &buffer)
{
    // TODO: Implement select char reading
}

bool RequestUserBanInfoPacket::isValid() const
{
    return true;
}