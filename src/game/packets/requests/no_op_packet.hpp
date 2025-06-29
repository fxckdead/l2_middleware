// src/game/packets/requests/no_op_packet.hpp
#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>
#include <vector>

// NoOpPacket - Handles ping packets (opcode 0x00)
// Client sends ping data and expects the same data echoed back
class NoOpPacket : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x0;
    std::vector<uint8_t> ping_data_;

public:
    NoOpPacket() = default;

    // ReadablePacket interface implementation (matches existing pattern)
    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;

    // Validation (matches existing pattern)
    bool isValid() const;
    
    // Get ping data for response
    const std::vector<uint8_t>& getPingData() const { return ping_data_; }
};