#include "skill_cool_time.hpp"
#include <iostream>

// Constructor
SkillCoolTime::SkillCoolTime(const Player* player)
    : player_(player)
{
    if (!player_)
    {
        throw std::invalid_argument("Player cannot be null for SkillCoolTime packet");
    }
}

void SkillCoolTime::write(SendablePacketBuffer &buffer)
{
    // Write packet header
    buffer.writeUInt8(PACKET_ID); // 0xC7 SkillCoolTime

    std::cout << "[SkillCoolTime] Sending skill cooldowns for: " << player_->getName() << std::endl;

    // Following L2J Mobius SkillCoolTime.java structure EXACTLY
    
    // 1. Skill count (as int, not uint32)
    int32_t skill_count = 0; // TODO: Implement actual skill system
    buffer.writeInt32(skill_count);
    
    // 2. Skill cooldown data (none for now)
    // TODO: When skill system is implemented, iterate through skills with cooldowns:
    // for each skill with cooldown:
    //   - Skill ID (int)
    //   - Skill level (int)
    //   - Reuse delay (remaining time in seconds)
    //   - Reuse group (remaining time in seconds)
    // This matches L2J Mobius structure:
    // buffer.writeInt(ts.getSkillId());
    // buffer.writeInt(ts.getSkillLevel());
    // buffer.writeInt((int) (reuse > 0 ? reuse : remaining) / 1000);
    // buffer.writeInt(Math.max(1, (int) remaining / 1000));

    std::cout << "[SkillCoolTime] Skill cooldowns sent successfully (" << skill_count << " skills)" << std::endl;
}

size_t SkillCoolTime::getSize() const
{
    // Calculate packet size based on L2J Mobius structure
    size_t size = 1; // opcode

    // Fixed-size fields (exactly like L2J Mobius)
    size += 4; // Skill count (int)
    
    // Skill cooldown data (none for now)
    // TODO: Add size calculation for actual skills when skill system is implemented
    // Each skill entry: 4 ints = 16 bytes

    return size;
} 