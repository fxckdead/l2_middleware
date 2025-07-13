#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

// ShowMiniMap - Server response to show/enable minimap (sent when client requests 0xCD)
// Based on L2J Mobius: player.sendPacket(new ShowMiniMap(1665));
class ShowMiniMap : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x9D; // ShowMiniMap packet ID
    int map_id_;

public:
    // Constructor
    explicit ShowMiniMap(int mapId = 1665);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;
}; 