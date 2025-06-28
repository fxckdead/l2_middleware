// src/game/packets/requests/no_op_packet.cpp
#include "no_op_packet.hpp"

// ReadablePacket interface implementation
uint8_t NoOpPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> NoOpPacket::getExPacketId() const
{
    return std::nullopt;
}

void NoOpPacket::read(ReadablePacketBuffer &buffer)
{
    // Read all remaining data as ping data that needs to be echoed back
    ping_data_.clear();
    while (buffer.getRemainingLength() > 0) {
        ping_data_.push_back(buffer.readByte());
    }
}

// Validation
bool NoOpPacket::isValid() const
{
    // Ping packets are always valid
    return true;
}