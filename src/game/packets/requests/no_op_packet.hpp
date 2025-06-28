// src/game/packets/requests/no_op_packet.hpp
#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

// NoOpPacket - Fallback packet for unknown packet types
// Matches pattern from existing login server packets
class NoOpPacket : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xFF;

public:
    NoOpPacket() = default;

    // ReadablePacket interface implementation (matches existing pattern)
    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;

    // Validation (matches existing pattern)
    bool isValid() const;
};