#include "enter_world_packet.hpp"

uint8_t EnterWorldPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> EnterWorldPacket::getExPacketId() const
{
    return std::nullopt;
}

void EnterWorldPacket::read(ReadablePacketBuffer &buffer)
{
    // NoOp packet - consume any remaining data but don't process it
    // This is a fallback for unknown packets
}

// Validation
bool EnterWorldPacket::isValid() const
{
    // NoOp packets are always "valid" since they're fallbacks
    return true;
}