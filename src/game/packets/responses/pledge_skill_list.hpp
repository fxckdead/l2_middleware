#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <vector>

// PledgeSkillList - Server response with clan skills
// Shows available clan skills to the client
class PledgeSkillList : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xFE;      // Extended packet prefix
    static constexpr uint16_t EX_PACKET_ID = 0x39;  // Extended packet sub-opcode
    const Player* player_;
    
    // Skill data structure (matches L2J Mobius)
    struct SkillData {
        uint32_t displayId;
        uint32_t displayLevel;
    };
    
    std::vector<SkillData> skills_;
    
    void buildSkillList();

public:
    // Constructor - create with player data
    explicit PledgeSkillList(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    uint16_t getExtendedPacketId() const override { return EX_PACKET_ID; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 