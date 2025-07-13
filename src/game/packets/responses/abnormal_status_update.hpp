#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <vector>

// AbnormalStatusUpdate - Server response with abnormal status effects
// Shows status effects (buffs, debuffs) to the client
// Based on L2J Mobius AbnormalStatusUpdate.java implementation
class AbnormalStatusUpdate : public SendablePacket
{
public:
    // Abnormal effect data structure (matches L2J Mobius exactly)
    struct AbnormalEffect
    {
        uint32_t skillId;      // skill display ID (int in L2J)
        uint16_t skillLevel;   // skill display level (short in L2J)
        uint32_t duration;     // remaining time in seconds (int in L2J)
    };

private:
    static constexpr uint8_t PACKET_ID = 0x85; // AbnormalStatusUpdate - Interlude Update 3
    const Player* player_;
    std::vector<AbnormalEffect> effects_;

public:
    // Constructor - create with player data
    explicit AbnormalStatusUpdate(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;

private:
    void buildEffectList();
}; 