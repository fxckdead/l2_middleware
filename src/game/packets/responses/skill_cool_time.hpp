#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <vector>

// SkillCoolTime - Server response with skill cooldown information
// Manages skill cooldowns and reuse delays
class SkillCoolTime : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xC7; // SkillCoolTime - Interlude Update 3
    const Player* player_;

public:
    // Constructor - create with player data
    explicit SkillCoolTime(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 