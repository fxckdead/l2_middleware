// src/game/packets/responses/shortcut_init.hpp
#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <memory>
#include <vector>

// ShortcutInit packet (opcode 0x45)
// Sends skill/item shortcuts to the client
class ShortcutInit : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x45;
    const Player* player_;
    
    // Shortcut types (matches L2J Mobius)
    enum class ShortcutType {
        ITEM = 1,
        SKILL = 2,
        ACTION = 3,
        MACRO = 4,
        RECIPE = 5
    };
    
    // Shortcut data structure (matches L2J Mobius)
    struct ShortcutData {
        ShortcutType type;
        uint32_t slot;        // slot + (page * 12)
        uint32_t id;          // item/skill/action ID
        uint32_t level;       // skill level or item count
        uint8_t subLevel;     // skill sublevel (only for skills)
        uint32_t sharedReuseGroup; // shared reuse group (only for skills)
        uint32_t characterType; // character type (only for items)
        uint16_t enchantLevel; // enchant level (only for items)
        uint16_t augmentation; // augmentation (only for items)
    };
    
    std::vector<ShortcutData> shortcuts_;
    
    void buildShortcuts();

public:
    explicit ShortcutInit(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    bool shouldWriteOpcodeAutomatically() const override { return true; }
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;
}; 