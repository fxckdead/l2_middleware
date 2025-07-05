#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>

// ValidateLocation - Server response to resync player position
// Critical for ensuring client/server position synchronization
class ValidateLocation : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x79; // ValidateLocation - Interlude Update 3
    const Player* player_;

public:
    // Constructor - create with player data
    explicit ValidateLocation(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 