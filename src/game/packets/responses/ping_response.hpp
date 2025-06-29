#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <vector>
#include <cstdint>

// PingResponse - Simple response to ping packets from clients
// Echoes back the ping data to confirm connectivity
class PingResponse : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x00; // Same as ping packet

    std::vector<uint8_t> ping_data_;

public:
    // Constructor
    explicit PingResponse(const std::vector<uint8_t>& ping_data);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;

    // Debug string representation
    std::string toString() const;
}; 