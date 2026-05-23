#include "user_info.hpp"
#include <iostream>

// Constructor
UserInfo::UserInfo(const Player* player)
    : player_(player)
{
    if (!player_)
    {
        throw std::invalid_argument("Player cannot be null for UserInfo packet");
    }
}

void UserInfo::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class

    std::cout << "[UserInfo] Sending user info for: " << player_->getName() 
              << " (ID: " << player_->getObjectId() << ")" << std::endl;

    // Following L2J Mobius UserInfo.java structure EXACTLY
    
    // 1. Position coordinates
    buffer.writeInt32(player_->getX());
    buffer.writeInt32(player_->getY());
    buffer.writeInt32(player_->getZ());
    
    // 2. Vehicle ID (for mounted players)
    buffer.writeInt32(0); // TODO: Implement mount system
    
    // 3. Object ID
    buffer.writeInt32(player_->getObjectId());
    
    // 4. Character name (regular string, not UTF-16)
    buffer.writeCUtf16leString(player_->getName());
    
    // 5. Race
    buffer.writeInt32(player_->getRace());
    
    // 6. Sex (0=male, 1=female)
    buffer.writeInt32(player_->getSex());
    
    // 7. Base class
    buffer.writeInt32(player_->getClassId());
    
    // 8. Level
    buffer.writeInt32(player_->getLevel());
    
    // 9. EXP (long)
    buffer.writeInt64(player_->getExp());
    
    // 10. Stats
    buffer.writeInt32(player_->getStr());
    buffer.writeInt32(player_->getDex());
    buffer.writeInt32(player_->getCon());
    buffer.writeInt32(player_->getInt());
    buffer.writeInt32(player_->getWit());
    buffer.writeInt32(player_->getMen());
    
    // 11. HP/MP
    buffer.writeInt32(player_->getMaxHp());
    buffer.writeInt32(static_cast<uint32_t>(player_->getCurrentHp()));
    buffer.writeInt32(player_->getMaxMp());
    buffer.writeInt32(static_cast<uint32_t>(player_->getCurrentMp()));
    
    // 12. SP
    buffer.writeInt32(static_cast<uint32_t>(player_->getSp()));
    
    // 13. Load (stub values)
    buffer.writeInt32(0); // Current load
    buffer.writeInt32(80); // Max load
    
    // 14. Weapon equipped (20=no weapon, 40=weapon equipped)
    buffer.writeInt32(20); // TODO: Check if weapon is equipped
    
    // 15. Paperdoll object IDs (equipment slots)
    for (int i = 0; i < 17; ++i) {
        buffer.writeInt32(0); // TODO: Implement equipment system
    }
    
    // 16. Paperdoll display IDs (equipment visual IDs)
    for (int i = 0; i < 17; ++i) {
        buffer.writeInt32(0); // TODO: Implement equipment system
    }
    
    // 17. C6 new fields (14 shorts)
    for (int i = 0; i < 14; ++i) {
        buffer.writeInt16(0);
    }
    
    // 18. Right hand augmentation
    buffer.writeInt32(0); // TODO: Implement augmentation system
    
    // 19. More C6 fields (12 shorts) — Mobius UserInfo.java:150-161 writes exactly 12,
    // not 13. The extra short was shifting every subsequent field by 2 bytes,
    // which caused the client to read garbage for runSpd/walkSpd and to refuse
    // walk animation while still allowing rotation.
    for (int i = 0; i < 12; ++i) {
        buffer.writeInt16(0);
    }
    
    // 20. Right hand augmentation (duplicate)
    buffer.writeInt32(0); // TODO: Implement augmentation system
    
    // 21. More C6 fields (4 shorts)
    for (int i = 0; i < 4; ++i) {
        buffer.writeInt16(0);
    }
    
    // 22. Combat stats (stub values)
    buffer.writeInt32(100); // PAtk
    buffer.writeInt32(300); // PAtkSpd
    buffer.writeInt32(50);  // PDef
    buffer.writeInt32(10);  // EvasionRate
    buffer.writeInt32(80);  // Accuracy
    buffer.writeInt32(5);   // CriticalHit
    buffer.writeInt32(50);  // MAtk
    buffer.writeInt32(200); // MAtkSpd
    buffer.writeInt32(300); // PAtkSpd (duplicate)
    buffer.writeInt32(30);  // MDef
    
    // 23. PvP info
    buffer.writeInt32(player_->getPvpFlag());
    buffer.writeInt32(player_->getKarma());
    
    // 24. Movement speeds (stub values)
    buffer.writeInt32(120); // Run speed
    buffer.writeInt32(80);  // Walk speed
    buffer.writeInt32(100); // Swim run speed
    buffer.writeInt32(60);  // Swim walk speed
    buffer.writeInt32(0);   // Fly run speed
    buffer.writeInt32(0);   // Fly walk speed
    buffer.writeInt32(0);   // Fly run speed (duplicate)
    buffer.writeInt32(0);   // Fly walk speed (duplicate)
    
    // 25. Multipliers (stub values)
    buffer.writeFloat64(1.0); // Movement speed multiplier
    buffer.writeFloat64(1.0); // Attack speed multiplier
    buffer.writeFloat64(12.0); // Collision radius
    buffer.writeFloat64(23.0); // Collision height
    
    // 26. Appearance
    buffer.writeInt32(player_->getHairStyle());
    buffer.writeInt32(player_->getHairColor());
    buffer.writeInt32(player_->getFace());
    buffer.writeInt32(0); // Builder level (GM level)
    
    // 27. Title
    buffer.writeCUtf16leString(std::string("")); // TODO: Implement title system
    
    // 28. Clan info
    buffer.writeInt32(player_->getClanId());
    buffer.writeInt32(0); // Clan crest ID
    buffer.writeInt32(0); // Ally ID
    buffer.writeInt32(0); // Ally crest ID
    
    // 29. Relation (clan leader, siege flags)
    buffer.writeInt32(0); // TODO: Implement clan relations
    
    // 30. Mount and store
    buffer.writeInt8(0); // Mount type
    buffer.writeInt8(0); // Private store type
    buffer.writeInt8(0); // Has dwarven craft
    
    // 31. PvP kills
    buffer.writeInt32(player_->getPkKills());
    buffer.writeInt32(player_->getPvpKills());
    
    // 32. Cubics
    buffer.writeInt16(0); // Cubic count
    // TODO: Iterate through cubics if any
    
    // 33. Party match room
    buffer.writeInt8(0); // Is in party match room
    
    // 34. Abnormal visual effects
    buffer.writeInt32(0); // TODO: Implement abnormal effects
    
    // 35. Zone and clan privileges
    buffer.writeInt8(0); // Is in water zone
    buffer.writeInt32(0); // Clan privileges
    
    // 36. Recommendations
    buffer.writeInt16(0); // Recommendations remaining
    buffer.writeInt16(0); // Recommendations received
    
    // 37. Mount NPC ID
    buffer.writeInt32(0); // TODO: Implement mount system
    
    // 38. Inventory and class
    buffer.writeUInt16(80); // Inventory limit (default 80)
    buffer.writeInt32(player_->getClassId());
    buffer.writeInt32(0); // Special effects
    
    // 39. CP (Combat Points) - stub values
    buffer.writeInt32(100); // Max CP
    buffer.writeInt32(100); // Current CP
    
    // 40. Enchant effect and team
    buffer.writeInt8(0); // Enchant effect
    buffer.writeInt8(0); // Team ID
    
    // 41. Clan crest large
    buffer.writeInt32(0); // TODO: Implement clan crest system
    
    // 42. Noble and hero
    buffer.writeInt8(0); // Is noble
    buffer.writeInt8(0); // Is hero
    
    // 43. Fishing
    buffer.writeInt8(0); // Is fishing
    buffer.writeInt32(0); // Fishing X
    buffer.writeInt32(0); // Fishing Y
    buffer.writeInt32(0); // Fishing Z
    
    // 44. Colors
    buffer.writeInt32(0); // Name color
    buffer.writeInt8(0); // Is running
    buffer.writeInt32(0); // Pledge class
    buffer.writeInt32(0); // Pledge type
    buffer.writeInt32(0); // Title color
    
    // 45. Cursed weapon
    buffer.writeInt32(0); // TODO: Implement cursed weapon system

    std::cout << "[UserInfo] User info sent successfully" << std::endl;
}

size_t UserInfo::getSize() const
{
    // Calculate packet size based on L2J Mobius structure
    size_t size = 1; // opcode

    // Position and vehicle
    size += 4 * 4; // X, Y, Z, Vehicle ID
    
    // Object ID and name
    size += 4; // Object ID
    size += (player_->getName().length() + 1) * 2; // Name (UTF-16LE + null)
    
    // Basic info
    size += 4 * 6; // Race, Sex, BaseClass, Level, EXP (8 bytes), Stats (6 * 4)
    
    // HP/MP/SP/Load
    size += 4 * 6; // MaxHP, CurrentHP, MaxMP, CurrentMP, SP, CurrentLoad, MaxLoad
    
    // Weapon and equipment
    size += 4; // Weapon equipped
    size += 4 * 17; // Paperdoll object IDs
    size += 4 * 17; // Paperdoll display IDs
    
    // C6 fields
    size += 2 * 14; // 14 shorts
    size += 4; // Right hand augmentation
    size += 2 * 12; // 12 shorts (matches Mobius UserInfo.java:150-161, was 13 — bug)
    size += 4; // Right hand augmentation (duplicate)
    size += 2 * 4; // 4 shorts
    
    // Combat stats
    size += 4 * 10; // Combat stats
    
    // PvP and movement
    size += 4 * 2; // PvP flag, Karma
    size += 4 * 8; // Movement speeds
    
    // Multipliers and collision
    size += 8 * 4; // Multipliers and collision (doubles)
    
    // Appearance and title
    size += 4 * 3; // Hair style, color, face
    size += 4; // Builder level
    size += 2; // Title (empty string, UTF-16LE + null)
    
    // Clan info
    size += 4 * 4; // Clan ID, crest, ally ID, ally crest
    size += 4; // Relation
    
    // Mount and store
    size += 1 * 3; // Mount type, store type, dwarven craft
    
    // PvP kills and cubics
    size += 4 * 2; // PK kills, PvP kills
    size += 2; // Cubic count
    
    // Party and effects
    size += 1; // Party match room
    size += 4; // Abnormal effects
    size += 1; // Water zone
    size += 4; // Clan privileges
    
    // Recommendations and mount
    size += 2 * 2; // Recommendations
    size += 4; // Mount NPC ID
    
    // Inventory and class
    size += 2; // Inventory limit
    size += 4 * 2; // Class ID, special effects
    
    // CP and effects
    size += 4 * 2; // Max CP, Current CP
    size += 1 * 2; // Enchant effect, team
    
    // Clan crest and status
    size += 4; // Clan crest large
    size += 1 * 2; // Noble, hero
    
    // Fishing
    size += 1; // Is fishing
    size += 4 * 3; // Fishing coordinates
    
    // Colors and cursed weapon
    size += 4; // Name color
    size += 1; // Is running
    size += 4 * 3; // Pledge class, type, title color
    size += 4; // Cursed weapon

    return size;
} 