#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

// ActionFailed - Server response to indicate action completion
// Tells the client that an action has completed (successfully or failed)
// This is crucial for removing loading screens and updating client state
class ActionFailed : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x25; // ActionFailed - Interlude Update 3

public:
    // Constructor
    explicit ActionFailed();

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 