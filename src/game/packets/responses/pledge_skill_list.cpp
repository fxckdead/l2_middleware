#include "pledge_skill_list.hpp"
#include <iostream>

// Constructor
PledgeSkillList::PledgeSkillList(const Player* player)
    : player_(player)
{
    if (!player_)
    {
        throw std::invalid_argument("Player cannot be null for PledgeSkillList packet");
    }
    buildSkillList();
}

void PledgeSkillList::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class

    std::cout << "[PledgeSkillList] Sending clan skills for: " << player_->getName() << std::endl;

    // Following L2J Mobius PledgeSkillList.java structure EXACTLY
    
    // 1. Skill count (int)
    buffer.writeUInt32(static_cast<uint32_t>(skills_.size()));
    
    // 2. Skill data
    for (const auto& skill : skills_)
    {
        buffer.writeUInt32(skill.displayId);
        buffer.writeUInt32(skill.displayLevel);
    }

    std::cout << "[PledgeSkillList] Clan skills sent successfully (" << skills_.size() << " skills)" << std::endl;
}

size_t PledgeSkillList::getSize() const
{
    // Calculate packet size based on L2J Mobius structure
    size_t size = 3; // Extended opcode (0xFE + 16-bit sub-opcode)

    // Fixed-size fields
    size += 4; // Skill count (int)
    
    // Skill data
    size += skills_.size() * 8; // Each skill: displayId(4) + displayLevel(4)

    return size;
}

void PledgeSkillList::buildSkillList()
{
    // For now, return empty skill list since we don't have a clan system implemented
    // TODO: Implement actual clan skill loading from database/player data
    skills_.clear();
    
    // Example clan skills (commented out for now):
    /*
    // Clan skill: Clan Harmony
    skills_.push_back({
        190,   // displayId (Clan Harmony)
        1      // displayLevel
    });
    
    // Clan skill: Clan Vitality
    skills_.push_back({
        191,   // displayId (Clan Vitality)
        1      // displayLevel
    });
    
    // Clan skill: Clan Agility
    skills_.push_back({
        192,   // displayId (Clan Agility)
        1      // displayLevel
    });
    */
} 