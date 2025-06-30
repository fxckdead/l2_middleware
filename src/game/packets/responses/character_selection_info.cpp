#include "character_selection_info.hpp"
#include "../../server/character_database_manager.hpp"
#include <iostream>

// Constructor
CharacterSelectionInfo::CharacterSelectionInfo(const std::vector<CharacterInfo>& characters)
    : characters_(characters)
{
}

// Static factory method for creating character list from database
std::unique_ptr<CharacterSelectionInfo> CharacterSelectionInfo::createFromDatabase(CharacterDatabaseManager* char_db, const std::string& account_name)
{
    std::vector<CharacterInfo> characters;
    
    if (char_db) {
        // Get all characters for this account from the database
        characters = char_db->getCharactersForAccount(account_name);
    }
    
    return std::make_unique<CharacterSelectionInfo>(characters);
}

void CharacterSelectionInfo::write(SendablePacketBuffer &buffer)
{
    // Write packet header - using 0x13 for Interlude Update 3
    buffer.writeUInt8(PACKET_ID);  // 0x13 CharacterSelectionInfo
    
    // Interlude Update 3 CharacterSelectionInfo packet structure
    // Based on L2J and other server implementations
    
    uint32_t char_count = static_cast<uint32_t>(characters_.size());
    buffer.writeUInt32(char_count);                // Number of characters
    
    // Write each character's data
    for (const auto& character : characters_) {
        // Character name (UTF-16LE, null-terminated)
        std::u16string name_utf16(character.name.begin(), character.name.end());
        for (char16_t c : name_utf16) {
            buffer.writeUInt16(static_cast<uint16_t>(c));
        }
        buffer.writeUInt16(0); // null terminator
        
        // Character stats
        buffer.writeUInt32(character.char_id);           // Character ID
        buffer.writeUInt32(character.login_name.length()); // Login name length
        for (char c : character.login_name) {            // Login name (UTF-8)
            buffer.writeUInt8(static_cast<uint8_t>(c));
        }
        buffer.writeUInt32(character.session_id);        // Session ID
        buffer.writeUInt32(character.clan_id);           // Clan ID
        buffer.writeUInt32(character.builder_level);     // Builder level
        buffer.writeUInt32(character.sex);               // Sex (0=male, 1=female)
        buffer.writeUInt32(character.race);              // Race
        buffer.writeUInt32(character.class_id);          // Class ID
        buffer.writeUInt32(character.active);            // Active flag
        
        // Position
        buffer.writeUInt32(character.x);                 // X coordinate
        buffer.writeUInt32(character.y);                 // Y coordinate
        buffer.writeUInt32(character.z);                 // Z coordinate
        
        // Stats
        buffer.writeFloat64(character.current_hp);       // Current HP
        buffer.writeFloat64(character.current_mp);       // Current MP
        buffer.writeUInt64(character.sp);                // SP
        buffer.writeUInt64(character.exp);               // Experience
        buffer.writeUInt32(character.level);             // Level
        buffer.writeUInt32(character.karma);             // Karma
        buffer.writeUInt32(character.pk_kills);          // PK kills
        buffer.writeUInt32(character.pv_kills);          // PvP kills
        
        // Equipment (paperdoll) - 16 slots
        for (uint32_t item_id : character.paperdoll_item_ids) {
            buffer.writeUInt32(item_id);
        }
    }
    
    // Additional packet data after character list
    buffer.writeUInt32(7);                         // Max characters allowed
    buffer.writeUInt8(0);                          // Active character index (0 = none)
    buffer.writeUInt8(2);                          // 0x02 = premium account (auto-learn skills)
    buffer.writeUInt32(0);                         // 0x00 = not on waiting list
    buffer.writeUInt32(0);                         // 0x00 = can play
    
    // Structure: 1 + 4 + (char_count * character_data) + 4 + 1 + 1 + 4 + 4 = 19 base bytes for 0 characters
}

size_t CharacterSelectionInfo::getSize() const
{
    // Packet size: opcode + char_count + character_data + additional_fields
    size_t base_size = 1 + 4 + 4 + 1 + 1 + 4 + 4; // 19 bytes base
    
    // Calculate character data size
    size_t character_data_size = 0;
    for (const auto& character : characters_) {
        character_data_size += (character.name.length() + 1) * 2; // Name (UTF-16LE + null terminator)
        character_data_size += 4;                          // Character ID
        character_data_size += 4 + character.login_name.length(); // Login name length + name
        character_data_size += 4;                          // Session ID
        character_data_size += 4;                          // Clan ID
        character_data_size += 4;                          // Builder level
        character_data_size += 4;                          // Sex
        character_data_size += 4;                          // Race
        character_data_size += 4;                          // Class ID
        character_data_size += 4;                          // Active flag
        character_data_size += 4 * 3;                      // Position (x, y, z)
        character_data_size += 8 * 2;                      // HP, MP (doubles)
        character_data_size += 8 * 2;                      // SP, EXP (uint64)
        character_data_size += 4 * 4;                      // Level, Karma, PK, PvP
        character_data_size += 16 * 4;                     // Equipment (16 slots * 4 bytes)
    }
    
    return base_size + character_data_size;
} 