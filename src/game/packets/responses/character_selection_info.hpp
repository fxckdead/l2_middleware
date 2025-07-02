#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>
#include <vector>
#include <string>

// Character data structure matching L2 Interlude packet format
struct CharacterInfo
{
    std::string name;
    uint32_t char_id;
    std::string login_name;
    uint32_t session_id;
    uint32_t clan_id;
    uint32_t builder_level;
    uint32_t sex;  // 0 = male, 1 = female
    uint32_t race; // 0 = human, 1 = elf, 2 = dark_elf, 3 = orc, 4 = dwarf
    uint32_t class_id;
    uint32_t active; // 0 = inactive, 1 = active

    // Position
    uint32_t x;
    uint32_t y;
    uint32_t z;

    // Stats
    double current_hp;
    double current_mp;
    double max_hp;
    double max_mp;
    uint64_t sp;
    uint64_t exp;
    uint32_t level;
    uint32_t karma;
    uint32_t pk_kills;
    uint32_t pv_kills;

    // Appearance data (essential for L2 character display)
    uint32_t hair_style;
    uint32_t hair_color;
    uint32_t face;

    // Base stats (often required for character display)
    uint32_t str_stat;
    uint32_t dex_stat;
    uint32_t con_stat;
    uint32_t int_stat;
    uint32_t wit_stat;
    uint32_t men_stat;

    // Equipment (paperdoll) - L2 needs both object IDs and item IDs
    std::vector<uint32_t> paperdoll_object_ids; // object IDs
    std::vector<uint32_t> paperdoll_item_ids;   // item IDs

    // Additional L2 fields
    long delete_timer;
    uint32_t augmentation_id;
    uint32_t base_class_id;
    uint32_t is_selected;    // Whether this character is the active/selected one
    uint32_t enchant_effect; // Visual enchant effect

    CharacterInfo()
    {
        paperdoll_object_ids.resize(16, 0); // Initialize 16 equipment object slots
        paperdoll_item_ids.resize(16, 0);   // Initialize 16 equipment item slots
        hair_style = 0;
        hair_color = 0;
        face = 0;
        str_stat = 10;
        dex_stat = 10;
        con_stat = 10;
        int_stat = 10;
        wit_stat = 10;
        men_stat = 10;
        max_hp = 100.0;
        max_mp = 100.0;
        delete_timer = 0;
        base_class_id = 0;
        is_selected = 0;
        enchant_effect = 0;
        augmentation_id = 0;
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
    explicit CharacterSelectionInfo(const std::vector<CharacterInfo> &characters);

    // Create with characters from database
    static std::unique_ptr<CharacterSelectionInfo> createFromDatabase(class CharacterDatabaseManager *char_db, const std::string &account_name);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
};