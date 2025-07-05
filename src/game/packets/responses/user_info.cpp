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
    buffer.writeUInt32(player_->getX());
    buffer.writeUInt32(player_->getY());
    buffer.writeUInt32(player_->getZ());
    
    // 2. Vehicle ID (for mounted players)
    buffer.writeUInt32(0); // TODO: Implement mount system
    
    // 3. Object ID
    buffer.writeUInt32(player_->getObjectId());
    
    // 4. Character name (regular string, not UTF-16)
    buffer.writeCUtf16leString(player_->getName());
    
    // 5. Race
    buffer.writeUInt32(player_->getRace());
    
    // 6. Sex (0=male, 1=female)
    buffer.writeUInt32(player_->getSex());
    
    // 7. Base class
    buffer.writeUInt32(player_->getClassId());
    
    // 8. Level
    buffer.writeUInt32(player_->getLevel());
    
    // 9. EXP (long)
    buffer.writeUInt64(player_->getExp());
    
    // 10. Stats
    buffer.writeUInt32(player_->getStr());
    buffer.writeUInt32(player_->getDex());
    buffer.writeUInt32(player_->getCon());
    buffer.writeUInt32(player_->getInt());
    buffer.writeUInt32(player_->getWit());
    buffer.writeUInt32(player_->getMen());
    
    // 11. HP/MP
    buffer.writeUInt32(player_->getMaxHp());
    buffer.writeUInt32(static_cast<uint32_t>(player_->getCurrentHp()));
    buffer.writeUInt32(player_->getMaxMp());
    buffer.writeUInt32(static_cast<uint32_t>(player_->getCurrentMp()));
    
    // 12. SP
    buffer.writeUInt32(static_cast<uint32_t>(player_->getSp()));
    
    // 13. Load (stub values)
    buffer.writeUInt32(0); // Current load
    buffer.writeUInt32(80); // Max load
    
    // 14. Weapon equipped (20=no weapon, 40=weapon equipped)
    buffer.writeUInt32(20); // TODO: Check if weapon is equipped
    
    // 15. Paperdoll object IDs (equipment slots)
    for (int i = 0; i < 18; ++i) {
        buffer.writeUInt32(0); // TODO: Implement equipment system
    }
    
    // 16. Paperdoll display IDs (equipment visual IDs)
    for (int i = 0; i < 18; ++i) {
        buffer.writeUInt32(0); // TODO: Implement equipment system
    }
    
    // 17. C6 new fields (14 shorts)
    for (int i = 0; i < 14; ++i) {
        buffer.writeUInt16(0);
    }
    
    // 18. Right hand augmentation
    buffer.writeUInt32(0); // TODO: Implement augmentation system
    
    // 19. More C6 fields (13 shorts)
    for (int i = 0; i < 13; ++i) {
        buffer.writeUInt16(0);
    }
    
    // 20. Right hand augmentation (duplicate)
    buffer.writeUInt32(0); // TODO: Implement augmentation system
    
    // 21. More C6 fields (4 shorts)
    for (int i = 0; i < 4; ++i) {
        buffer.writeUInt16(0);
    }
    
    // 22. Combat stats (stub values)
    buffer.writeUInt32(100); // PAtk
    buffer.writeUInt32(300); // PAtkSpd
    buffer.writeUInt32(50);  // PDef
    buffer.writeUInt32(10);  // EvasionRate
    buffer.writeUInt32(80);  // Accuracy
    buffer.writeUInt32(5);   // CriticalHit
    buffer.writeUInt32(50);  // MAtk
    buffer.writeUInt32(200); // MAtkSpd
    buffer.writeUInt32(300); // PAtkSpd (duplicate)
    buffer.writeUInt32(30);  // MDef
    
    // 23. PvP info
    buffer.writeUInt32(player_->getPvpFlag());
    buffer.writeUInt32(player_->getKarma());
    
    // 24. Movement speeds (stub values)
    buffer.writeUInt32(120); // Run speed
    buffer.writeUInt32(80);  // Walk speed
    buffer.writeUInt32(100); // Swim run speed
    buffer.writeUInt32(60);  // Swim walk speed
    buffer.writeUInt32(0);   // Fly run speed
    buffer.writeUInt32(0);   // Fly walk speed
    buffer.writeUInt32(0);   // Fly run speed (duplicate)
    buffer.writeUInt32(0);   // Fly walk speed (duplicate)
    
    // 25. Multipliers (stub values)
    buffer.writeFloat64(1.0); // Movement speed multiplier
    buffer.writeFloat64(1.0); // Attack speed multiplier
    buffer.writeFloat64(20.0); // Collision radius
    buffer.writeFloat64(30.0); // Collision height
    
    // 26. Appearance
    buffer.writeUInt32(player_->getHairStyle());
    buffer.writeUInt32(player_->getHairColor());
    buffer.writeUInt32(player_->getFace());
    buffer.writeUInt32(0); // Builder level (GM level)
    
    // 27. Title
    buffer.writeCUtf16leString(std::string("")); // TODO: Implement title system
    
    // 28. Clan info
    buffer.writeUInt32(player_->getClanId());
    buffer.writeUInt32(0); // Clan crest ID
    buffer.writeUInt32(0); // Ally ID
    buffer.writeUInt32(0); // Ally crest ID
    
    // 29. Relation (clan leader, siege flags)
    buffer.writeUInt32(0); // TODO: Implement clan relations
    
    // 30. Mount and store
    buffer.writeUInt8(0); // Mount type
    buffer.writeUInt8(0); // Private store type
    buffer.writeUInt8(0); // Has dwarven craft
    
    // 31. PvP kills
    buffer.writeUInt32(player_->getPkKills());
    buffer.writeUInt32(player_->getPvpKills());
    
    // 32. Cubics
    buffer.writeUInt16(0); // Cubic count
    // TODO: Iterate through cubics if any
    
    // 33. Party match room
    buffer.writeUInt8(0); // Is in party match room
    
    // 34. Abnormal visual effects
    buffer.writeUInt32(0); // TODO: Implement abnormal effects
    
    // 35. Zone and clan privileges
    buffer.writeUInt8(0); // Is in water zone
    buffer.writeUInt32(0); // Clan privileges
    
    // 36. Recommendations
    buffer.writeUInt16(0); // Recommendations remaining
    buffer.writeUInt16(0); // Recommendations received
    
    // 37. Mount NPC ID
    buffer.writeUInt32(0); // TODO: Implement mount system
    
    // 38. Inventory and class
    buffer.writeUInt16(80); // Inventory limit (default 80)
    buffer.writeUInt32(player_->getClassId());
    buffer.writeUInt32(0); // Special effects
    
    // 39. CP (Combat Points) - stub values
    buffer.writeUInt32(100); // Max CP
    buffer.writeUInt32(100); // Current CP
    
    // 40. Enchant effect and team
    buffer.writeUInt8(0); // Enchant effect
    buffer.writeUInt8(0); // Team ID
    
    // 41. Clan crest large
    buffer.writeUInt32(0); // TODO: Implement clan crest system
    
    // 42. Noble and hero
    buffer.writeUInt8(0); // Is noble
    buffer.writeUInt8(0); // Is hero
    
    // 43. Fishing
    buffer.writeUInt8(0); // Is fishing
    buffer.writeUInt32(0); // Fishing X
    buffer.writeUInt32(0); // Fishing Y
    buffer.writeUInt32(0); // Fishing Z
    
    // 44. Colors
    buffer.writeUInt32(0); // Name color
    buffer.writeUInt8(0); // Is running
    buffer.writeUInt32(0); // Pledge class
    buffer.writeUInt32(0); // Pledge type
    buffer.writeUInt32(0); // Title color
    
    // 45. Cursed weapon
    buffer.writeUInt32(0); // TODO: Implement cursed weapon system

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
    size += 4 * 18; // Paperdoll object IDs
    size += 4 * 18; // Paperdoll display IDs
    
    // C6 fields
    size += 2 * 14; // 14 shorts
    size += 4; // Right hand augmentation
    size += 2 * 13; // 13 shorts
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