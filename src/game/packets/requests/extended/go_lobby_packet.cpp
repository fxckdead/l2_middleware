#include "go_lobby_packet.hpp"

uint8_t GoLobbyPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> GoLobbyPacket::getExPacketId() const
{
    return std::nullopt;
}

void GoLobbyPacket::read(ReadablePacketBuffer &buffer)
{
    // NoOp packet - consume any remaining data but don't process it
    // This is a fallback for unknown packets
}

// Validation
bool GoLobbyPacket::isValid() const
{
    // NoOp packets are always "valid" since they're fallbacks
    return true;
}