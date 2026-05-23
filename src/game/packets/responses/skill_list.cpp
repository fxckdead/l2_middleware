#include "skill_list.hpp"
#include <iostream>

SkillList::SkillList(const Player* player)
{
    // For now, add some basic skills that every player should have
    // In a real implementation, this would read from player's skill database
    
    // Basic skills every character should have (examples from L2J)
    addSkill(1001, 1, true, false);   // Divine Protection (passive)
    addSkill(1002, 1, true, false);   // Blessing of Eva (passive)
    addSkill(1003, 1, false, false);  // Power Strike (active)
    addSkill(1004, 1, false, false);  // Mortal Blow (active)
    
    std::cout << "[SkillList] Created skill list with " << skills_.size() << " skills for player" << std::endl;
}

void SkillList::addSkill(uint32_t skillId, uint32_t level, bool passive, bool disabled)
{
    skills_.push_back({skillId, level, passive, disabled});
}

void SkillList::write(SendablePacketBuffer &buffer)
{
    // SkillList packet format (matches L2J Mobius exactly):
    // - uint32: skill_count
    // For each skill:
    //   - uint32: passive flag (0=active, 1=passive) 
    //   - uint32: skill_level
    //   - uint32: skill_id
    //   - uint8: disabled flag (0=enabled, 1=disabled)
    
    buffer.writeUInt32(static_cast<uint32_t>(skills_.size()));
    
    for (const auto& skill : skills_)
    {
        buffer.writeUInt32(skill.is_passive ? 1 : 0);  // passive flag
        buffer.writeUInt32(skill.skill_level);         // skill level
        buffer.writeUInt32(skill.skill_id);            // skill ID
        buffer.writeUInt8(skill.is_disabled ? 1 : 0);  // disabled flag
    }
    
    std::cout << "[SkillList] Sending skill list with " << skills_.size() << " skills" << std::endl;
}

size_t SkillList::getSize() const
{
    // Calculate packet size: skill count + skill data
    size_t size = 4; // skill count (uint32)
    
    for (const auto& skill : skills_)
    {
        size += 4; // passive flag (uint32)
        size += 4; // skill level (uint32) 
        size += 4; // skill ID (uint32)
        size += 1; // disabled flag (uint8)
    }
    
    return size;
} 