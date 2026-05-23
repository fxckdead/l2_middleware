#include "npc_info.hpp"
#include <iostream>

// Constructor for basic NPC (for testing - creates a dummy NPC)
NpcInfo::NpcInfo(uint32_t objectId, uint32_t displayId, uint32_t x, uint32_t y, uint32_t z, 
                 const std::string& name, const std::string& title)
    : m_objectId(objectId),
      m_displayId(displayId),
      m_isAttackable(true),
      m_x(x),
      m_y(y),
      m_z(z),
      m_heading(0),
      m_mAtkSpd(253),
      m_pAtkSpd(253),
      m_runSpd(120),
      m_walkSpd(50),
      m_swimRunSpd(120),
      m_swimWalkSpd(50),
      m_flyRunSpd(0),
      m_flyWalkSpd(0),
      m_moveMultiplier(1.0),
      m_attackSpeedMultiplier(1.0),
      m_collisionRadius(8.0),
      m_collisionHeight(23.0),
      m_rhand(0),
      m_chest(0),
      m_lhand(0),
      m_name(name),
      m_title(title),
      m_isRunning(false),
      m_isInCombat(false),
      m_isAlikeDead(false),
      m_isSummoned(false),
      m_abnormalVisualEffects(0),
      m_enchantEffect(0),
      m_isFlying(false)
{
}

void NpcInfo::write(SendablePacketBuffer& buffer)
{
    // Opcode is written automatically by base class
    
    std::cout << "[NpcInfo] Sending NPC info for: " << m_name 
              << " (ID: " << m_objectId << ", DisplayID: " << m_displayId << ")"
              << " at (" << m_x << ", " << m_y << ", " << m_z << ")" << std::endl;
    
    // Following L2J Mobius AbstractNpcInfo.java NpcInfo structure EXACTLY
    
    // 1. Object ID
    buffer.writeUInt32(m_objectId);
    
    // 2. NPC type ID (displayId + 1000000)
    buffer.writeUInt32(m_displayId + 1000000);
    
    // 3. Is attackable
    buffer.writeUInt32(m_isAttackable ? 1 : 0);
    
    // 4. Position
    buffer.writeUInt32(m_x);
    buffer.writeUInt32(m_y);
    buffer.writeUInt32(m_z);
    buffer.writeUInt32(m_heading);
    
    // 5. Unknown (always 0)
    buffer.writeUInt32(0);
    
    // 6. Attack speeds
    buffer.writeUInt32(m_mAtkSpd);
    buffer.writeUInt32(m_pAtkSpd);
    
    // 7. Movement speeds
    buffer.writeUInt32(m_runSpd);
    buffer.writeUInt32(m_walkSpd);
    buffer.writeUInt32(m_swimRunSpd);
    buffer.writeUInt32(m_swimWalkSpd);
    buffer.writeUInt32(m_flyRunSpd);
    buffer.writeUInt32(m_flyWalkSpd);
    buffer.writeUInt32(m_flyRunSpd);
    buffer.writeUInt32(m_flyWalkSpd);
    
    // 8. Movement multiplier
    buffer.writeFloat64(m_moveMultiplier);
    
    // 9. Attack speed multiplier
    buffer.writeFloat64(m_attackSpeedMultiplier);
    
    // 10. Collision
    buffer.writeFloat64(m_collisionRadius);
    buffer.writeFloat64(m_collisionHeight);
    
    // 11. Equipment
    buffer.writeUInt32(m_rhand);
    buffer.writeUInt32(m_chest);
    buffer.writeUInt32(m_lhand);
    
    // 12. Name above character (1=true)
    buffer.writeUInt8(1);
    
    // 13. Status flags
    buffer.writeUInt8(m_isRunning ? 1 : 0);
    buffer.writeUInt8(m_isInCombat ? 1 : 0);
    buffer.writeUInt8(m_isAlikeDead ? 1 : 0);
    buffer.writeUInt8(m_isSummoned ? 2 : 0);
    
    // 14. Name and title
    buffer.writeCUtf16leString(m_name);
    buffer.writeCUtf16leString(m_title);
    
    // 15. Title color (0=client default)
    buffer.writeUInt32(0);
    
    // 16. PvP flag and karma
    buffer.writeUInt32(0);
    buffer.writeUInt32(0);
    
    // 17. Abnormal visual effects
    buffer.writeUInt32(m_abnormalVisualEffects);
    
    // 18. Clan/ally info (simplified - no clan support)
    buffer.writeUInt32(0); // clan id
    buffer.writeUInt32(0); // crest id
    buffer.writeUInt32(0); // ally id
    buffer.writeUInt32(0); // ally crest
    
    // 19. Zone info (0=ground, 1=water, 2=flying)
    buffer.writeUInt8(m_isFlying ? 2 : 0);
    
    // 20. Team ID (0=none)
    buffer.writeUInt8(0);
    
    // 21. Collision (repeated)
    buffer.writeFloat64(m_collisionRadius);
    buffer.writeFloat64(m_collisionHeight);
    
    // 22. Enchant effect
    buffer.writeUInt32(m_enchantEffect);
    
    // 23. Flying flag
    buffer.writeUInt32(m_isFlying ? 1 : 0);
}

size_t NpcInfo::getSize() const
{
    // Calculate base size (fixed fields)
    size_t size = 1 + // packet id
                  4 + // object id
                  4 + // display id
                  4 + // is attackable
                  4 + 4 + 4 + 4 + // position + heading
                  4 + // unknown
                  4 + 4 + // attack speeds
                  4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + // movement speeds
                  8 + 8 + // multipliers
                  8 + 8 + // collision
                  4 + 4 + 4 + // equipment
                  1 + 1 + 1 + 1 + 1 + // flags
                  4 + 4 + 4 + 4 + // title color, pvp, karma, effects
                  4 + 4 + 4 + 4 + // clan info
                  1 + 1 + // zone, team
                  8 + 8 + // collision repeated
                  4 + 4; // enchant, flying
    
    // Add string sizes (UTF-16LE)
    size += 2 + (m_name.length() * 2);
    size += 2 + (m_title.length() * 2);
    
    return size;
} 