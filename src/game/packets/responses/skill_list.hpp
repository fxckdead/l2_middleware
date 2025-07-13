#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <vector>

// SkillList - Server packet to send player's skill list
// Critical packet that client expects to initialize skill UI and functionality
class SkillList : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x58; // SkillList - Interlude Update 3
    
    // Skill data structure (matches L2J Mobius exactly)
    struct SkillData {
        uint32_t skill_id;
        uint32_t skill_level;
        bool is_passive;
        bool is_disabled;
    };
    
    std::vector<SkillData> skills_;

public:
    // Constructor - create with player data
    explicit SkillList(const Player* player);
    
    // Add individual skill (for testing/manual construction)
    void addSkill(uint32_t skillId, uint32_t level, bool passive, bool disabled);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 