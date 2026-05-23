#include "character_selected.hpp"
#include <iostream>

// Constructor
CharacterSelected::CharacterSelected(const Player* player, uint32_t sessionId)
    : player_(player), sessionId_(sessionId)
{
    if (!player_)
    {
        throw std::invalid_argument("Player cannot be null for CharacterSelected packet");
    }
}

void CharacterSelected::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class

    std::cout << "[CharacterSelected] Sending character data for: " << player_->getName() 
              << " (ID: " << player_->getObjectId() << ")" << std::endl;

    // Write character data following L2J Mobius CharSelected.java format exactly
    // 1. Character name as null-terminated UTF-16LE string
    buffer.writeCUtf16leString(player_->getName());

    // 2. Character ID
    buffer.writeUInt32(player_->getObjectId());

    // 3. Character title as null-terminated UTF-16LE string
    buffer.writeCUtf16leString(std::string("")); // TODO: Implement title system

    // 4. Session ID
    buffer.writeUInt32(sessionId_);

    // 5. Clan ID
    buffer.writeUInt32(player_->getClanId());

    // 6. Builder level (0x00 = normal player)
    buffer.writeUInt32(0);

    // 7. Sex (0=male, 1=female)
    buffer.writeUInt32(player_->getSex());

    // 8. Race (0=human, 1=elf, 2=dark_elf, 3=orc, 4=dwarf)
    buffer.writeUInt32(player_->getRace());

    // 9. Class ID (current class)
    buffer.writeUInt32(player_->getClassId());

    // 10. Active status (1 = active)
    buffer.writeUInt32(1);

    // 11. Position coordinates
    buffer.writeUInt32(player_->getX());
    buffer.writeUInt32(player_->getY());
    buffer.writeUInt32(player_->getZ());

    // 12. Current HP (double)
    buffer.writeFloat64(player_->getCurrentHp());

    // 13. Current MP (double)
    buffer.writeFloat64(player_->getCurrentMp());

    // 14. SP (as int, not long for Interlude)
    buffer.writeUInt32(static_cast<uint32_t>(player_->getSp()));

    // 15. EXP (long)
    buffer.writeUInt64(player_->getExp());

    // 16. Level
    buffer.writeUInt32(player_->getLevel());

    // 17. Karma
    buffer.writeUInt32(player_->getKarma());

    // 18. PK kills
    buffer.writeUInt32(player_->getPkKills());

    // 19. INT stat
    buffer.writeUInt32(player_->getInt());

    // 20. STR stat
    buffer.writeUInt32(player_->getStr());

    // 21. CON stat
    buffer.writeUInt32(player_->getCon());

    // 22. MEN stat
    buffer.writeUInt32(player_->getMen());

    // 23. DEX stat
    buffer.writeUInt32(player_->getDex());

    // 24. WIT stat
    buffer.writeUInt32(player_->getWit());

    // 25. 30 reserved integers (matching Java implementation)
    for (int i = 0; i < 30; i++)
    {
        buffer.writeUInt32(0);
    }

    // 26. Additional reserved integer
    buffer.writeUInt32(0);

    // 27. Another reserved integer
    buffer.writeUInt32(0);

    // 28. Game time (minutes since server start, reset every 24 hours)
    // TODO: Implement proper game time system
    buffer.writeUInt32(0);

    // 29. Reserved integer
    buffer.writeUInt32(0);

    // 30. Class ID again
    buffer.writeUInt32(player_->getClassId());

    // 31-40. 10 more reserved integers (matching Java implementation)
    for (int i = 0; i < 10; i++)
    {
        buffer.writeUInt32(0);
    }

    std::cout << "[CharacterSelected] Character data sent successfully" << std::endl;
}

size_t CharacterSelected::getSize() const
{
    // Calculate packet size based on the data being sent
    size_t size = 1; // opcode

    // Character name (UTF-16LE + null terminator)
    size += (player_->getName().length() + 1) * 2;

    // Fixed-size fields
    size += 4; // Character ID
    size += 2; // Title (empty string, UTF-16LE + null)
    size += 4; // Session ID
    size += 4; // Clan ID
    size += 4; // Builder level
    size += 4; // Sex
    size += 4; // Race
    size += 4; // Class ID
    size += 4; // Active status
    size += 4 * 3; // X, Y, Z coordinates
    size += 8 * 2; // Current HP, MP (doubles)
    size += 4; // SP
    size += 8; // EXP (long)
    size += 4; // Level
    size += 4; // Karma
    size += 4; // PK kills
    size += 4 * 6; // INT, STR, CON, MEN, DEX, WIT
    size += 4 * 30; // 30 reserved integers
    size += 4 * 2; // 2 more reserved integers
    size += 4; // Game time
    size += 4; // Reserved
    size += 4; // Class ID again
    size += 4 * 10; // 10 more reserved integers

    return size;
} 