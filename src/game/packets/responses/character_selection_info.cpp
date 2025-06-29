#include "character_selection_info.hpp"
#include <iostream>

// Constructor
CharacterSelectionInfo::CharacterSelectionInfo(const std::vector<CharacterInfo>& characters)
    : characters_(characters)
{
}

// Static factory method for creating test character
std::unique_ptr<CharacterSelectionInfo> CharacterSelectionInfo::createWithTestCharacter(const std::string& account_name)
{
    // MINIMAL TEST: Send empty character list first
    std::vector<CharacterInfo> characters; // Empty list
    
    // TODO: Once empty screen works, add test character back
    
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
    
    // Write each character's data (for 0 characters, this loop won't execute)
    for (const auto& character : characters_) {
        // Character data would go here - ~300+ bytes per character
        // For now, we're testing with 0 characters so this is empty
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
    
    // Add character data size (each character is ~300+ bytes, but we have 0 for now)
    size_t character_data_size = characters_.size() * 0; // 0 bytes per character for now
    
    return base_size + character_data_size; // 19 bytes total for empty character list
} 