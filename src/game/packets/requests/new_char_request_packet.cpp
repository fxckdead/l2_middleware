#include "new_char_request_packet.hpp"

uint8_t NewCharRequestPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> NewCharRequestPacket::getExPacketId() const
{
    return std::nullopt;
}

void NewCharRequestPacket::read(ReadablePacketBuffer &buffer)
{
    // NoOp packet - consume any remaining data but don't process it
    // This is a fallback for unknown packets
}

// Validation
bool NewCharRequestPacket::isValid() const
{
    // NoOp packets are always "valid" since they're fallbacks
    return true;
}