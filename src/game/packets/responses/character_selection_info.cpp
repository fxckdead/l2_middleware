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
    
    // Character count
    uint32_t char_count = static_cast<uint32_t>(characters_.size());
    buffer.writeUInt32(char_count);
    
    std::cout << "[CharSelectionInfo] Sending " << char_count << " characters" << std::endl;
    
    // Find most recently accessed character for active selection
    int active_char_index = -1;
    if (!characters_.empty()) {
        active_char_index = 0; // Default to first character
    }
    
    // Write each character's data using EXACT L2 Interlude format
    for (size_t i = 0; i < characters_.size(); ++i) {
        const auto& character = characters_[i];
        
        std::cout << "[CharSelectionInfo] Character " << i << ": " << character.name 
                  << " ID=" << character.char_id 
                  << " HP=" << character.current_hp << "/" << character.max_hp 
                  << " MP=" << character.current_mp << "/" << character.max_mp << std::endl;
        
        // Character name as null-terminated UTF-16LE string
        buffer.writeCUtf16leString(character.name);
        
        // Character ID
        buffer.writeUInt32(character.char_id);
        
        // Login name as null-terminated UTF-16LE string  
        buffer.writeCUtf16leString(character.login_name);
        
        // Session ID
        buffer.writeUInt32(character.session_id);
        
        // Clan ID
        buffer.writeUInt32(character.clan_id);
        
        // Builder level (0x00 = normal player)
        buffer.writeUInt32(character.builder_level);
        
        // Sex (0=male, 1=female)
        buffer.writeUInt32(character.sex);
        
        // Race (0=human, 1=elf, 2=dark_elf, 3=orc, 4=dwarf)
        buffer.writeUInt32(character.race);
        
        // Class ID (current class)
        buffer.writeUInt32(character.class_id);
        
        // Server ID (always 1 for single server)
        buffer.writeUInt32(1);
        
        // Position
        buffer.writeUInt32(character.x);
        buffer.writeUInt32(character.y);
        buffer.writeUInt32(character.z);
        
        // Current HP (double)
        buffer.writeFloat64(character.current_hp);
        
        // Current MP (double)
        buffer.writeFloat64(character.current_mp);
        
        // SP (as int, not long for Interlude)
        buffer.writeUInt32(static_cast<uint32_t>(character.sp));
        
        // EXP (long)
        buffer.writeUInt64(character.exp);
        
        // Level
        buffer.writeUInt32(character.level);
        
        // Karma
        buffer.writeUInt32(character.karma);
        
        // PK kills
        buffer.writeUInt32(character.pk_kills);
        
        // PvP kills  
        buffer.writeUInt32(character.pv_kills);
        
        // Reserved bytes (9 zeros matching Java)
        for (int j = 0; j < 9; ++j) {
            buffer.writeUInt32(0);
        }
        
        // CRITICAL: Equipment paperdoll - Send 16 object IDs first
        for (uint32_t obj_id : character.paperdoll_object_ids) {
            buffer.writeUInt32(obj_id);
        }
        
        // CRITICAL: Equipment paperdoll - Send 16 item IDs second  
        for (uint32_t item_id : character.paperdoll_item_ids) {
            buffer.writeUInt32(item_id);
        }
        
        // Appearance data (essential for character display)
        buffer.writeUInt32(character.hair_style);
        buffer.writeUInt32(character.hair_color);
        buffer.writeUInt32(character.face);
        
        // Maximum HP (double) - CRITICAL missing field
        buffer.writeFloat64(character.max_hp);
        
        // Maximum MP (double) - CRITICAL missing field
        buffer.writeFloat64(character.max_mp);
        
        // Delete timer (0 = not being deleted, >0 = deletion time)
        buffer.writeUInt32(0);
        
        // Base class ID (for subclass system)
        buffer.writeUInt32(character.base_class_id);
        
        // Is this character selected/active?
        buffer.writeUInt32(static_cast<uint32_t>(i == active_char_index ? 1 : 0));
        
        // Enchant effect (visual weapon glow)
        buffer.writeUInt8(static_cast<uint8_t>(std::min(character.enchant_effect, 127u)));
        
        // Augmentation ID (weapon augmentation)
        buffer.writeUInt32(character.augmentation_id);
    }
}

size_t CharacterSelectionInfo::getSize() const
{
    // Packet size calculation - this is complex due to variable string lengths
    // For now, return a reasonable estimate
    size_t base_size = 1 + 4; // opcode + char_count
    
    // Each character has many more fields now
    for (const auto& character : characters_) {
        size_t char_size = 0;
        char_size += (character.name.length() + 1) * 2;        // Name (UTF-16LE + null)
        char_size += 4;                                        // Character ID
        char_size += (character.login_name.length() + 1) * 2;  // Login name (UTF-16LE + null)
        char_size += 4 * 8;                                    // Session, clan, builder, sex, race, class, server, x, y, z
        char_size += 8 * 4;                                    // current_hp, current_mp, max_hp, max_mp (doubles)
        char_size += 4 + 8 + 4 * 4;                           // sp, exp, level, karma, pk, pvp
        char_size += 4 * 9;                                    // Reserved bytes
        char_size += 4 * 32;                                   // Equipment (16 object + 16 item IDs)
        char_size += 4 * 3;                                    // Hair style, color, face
        char_size += 4 * 3;                                    // Delete timer, base class, selected
        char_size += 1 + 4;                                    // Enchant effect + augmentation
        base_size += char_size;
    }
    
    return base_size;
} 