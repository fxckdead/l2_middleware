#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>

// StatusUpdate - Server packet to update player's HP/MP/CP status
// Critical packet that client expects to know current health/mana status
class StatusUpdate : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x0E; // StatusUpdate - Interlude Update 3
    const Player* player_;

public:
    // Constructor - create with player data
    explicit StatusUpdate(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 