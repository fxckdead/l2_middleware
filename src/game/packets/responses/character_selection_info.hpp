#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>
#include <vector>
#include <string>

// Fake character data structure
struct CharacterInfo
{
    std::string name;
    uint32_t char_id;
    std::string login_name;
    uint32_t session_id;
    uint32_t clan_id;
    uint32_t builder_level;
    uint32_t sex;         // 0 = male, 1 = female
    uint32_t race;        // 0 = human, 1 = elf, 2 = dark_elf, 3 = orc, 4 = dwarf
    uint32_t class_id;
    uint32_t active;      // 0 = inactive, 1 = active
    
    // Position
    uint32_t x;
    uint32_t y; 
    uint32_t z;
    
    // Stats
    double current_hp;
    double current_mp;
    uint64_t sp;
    uint64_t exp;
    uint32_t level;
    uint32_t karma;
    uint32_t pk_kills;
    uint32_t pv_kills;
    
    // Equipment (paperdoll) - simplified for now
    std::vector<uint32_t> paperdoll_item_ids;  // 16 slots
    
    CharacterInfo()
    {
        paperdoll_item_ids.resize(16, 0); // Initialize 16 equipment slots with 0 (no item)
    }
};

// CharacterSelectionInfo - Server response after successful RequestLogin
// Shows available characters for the authenticated account
class CharacterSelectionInfo : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x13; // CharacterSelectionInfo - Interlude Update 3
    std::vector<CharacterInfo> characters_;

public:
    // Constructor - create with character data
    explicit CharacterSelectionInfo(const std::vector<CharacterInfo>& characters);
    
    // Create with characters from database
    static std::unique_ptr<CharacterSelectionInfo> createFromDatabase(class CharacterDatabaseManager* char_db, const std::string& account_name);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 