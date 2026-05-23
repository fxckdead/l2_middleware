// src/game/packets/responses/shortcut_init.cpp
#include "shortcut_init.hpp"
#include <iostream>

ShortcutInit::ShortcutInit(const Player* player)
    : player_(player)
{
    if (!player_) {
        throw std::invalid_argument("Player cannot be null for ShortcutInit packet");
    }
    buildShortcuts();
}

void ShortcutInit::write(SendablePacketBuffer& buffer)
{
    // Packet structure: shortcutCount + shortcuts
    // Each shortcut has different structure based on type (matches L2J Mobius)
    
    // Write shortcut count
    buffer.writeInt32(static_cast<int32_t>(shortcuts_.size()));
    
    // Write each shortcut
    for (const auto& shortcut : shortcuts_)
    {
        // Write type and slot (common for all types)
        buffer.writeInt32(static_cast<int32_t>(shortcut.type));
        buffer.writeInt32(static_cast<int32_t>(shortcut.slot));
        
        // Write type-specific data
        switch (shortcut.type)
        {
            case ShortcutType::ITEM:
            {
                buffer.writeInt32(static_cast<int32_t>(shortcut.id));
                buffer.writeInt32(static_cast<int32_t>(shortcut.level)); // item count
                buffer.writeInt32(-1); // shared reuse group (not used for items)
                buffer.writeInt32(static_cast<int32_t>(shortcut.characterType));
                buffer.writeInt32(0); // unknown
                buffer.writeInt16(static_cast<int16_t>(shortcut.enchantLevel));
                buffer.writeInt16(static_cast<int16_t>(shortcut.augmentation));
                break;
            }
            case ShortcutType::SKILL:
            {
                buffer.writeInt32(static_cast<int32_t>(shortcut.id));
                buffer.writeInt32(static_cast<int32_t>(shortcut.level));
                buffer.write(static_cast<uint8_t>(shortcut.subLevel)); // C5
                buffer.writeInt32(static_cast<int32_t>(shortcut.sharedReuseGroup));
                break;
            }
            case ShortcutType::ACTION:
            case ShortcutType::MACRO:
            case ShortcutType::RECIPE:
            {
                buffer.writeInt32(static_cast<int32_t>(shortcut.id));
                buffer.writeInt32(static_cast<int32_t>(shortcut.level));
                break;
            }
        }
    }
}

size_t ShortcutInit::getSize() const
{
    // Calculate packet size: 4 bytes for count + variable size for shortcuts
    size_t size = 4; // shortcut count
    
    for (const auto& shortcut : shortcuts_)
    {
        size += 8; // type + slot (common for all types)
        
        switch (shortcut.type)
        {
            case ShortcutType::ITEM:
                size += 28; // id(4) + level(4) + -1(4) + charType(4) + 0(4) + enchant(2) + augment(2)
                break;
            case ShortcutType::SKILL:
                size += 13; // id(4) + level(4) + subLevel(1) + reuseGroup(4)
                break;
            case ShortcutType::ACTION:
            case ShortcutType::MACRO:
            case ShortcutType::RECIPE:
                size += 8; // id(4) + level(4)
                break;
        }
    }
    
    return size;
}

void ShortcutInit::buildShortcuts()
{
    // For now, return empty shortcuts since we don't have a shortcut system implemented
    // TODO: Implement actual shortcut loading from database/player data
    shortcuts_.clear();
    
    // Example shortcuts (commented out for now):
    /*
    // Basic attack skill shortcut
    shortcuts_.push_back({
        ShortcutType::SKILL,  // type
        0,                    // slot (slot 0, page 0)
        1,                    // id (skill ID for basic attack)
        1,                    // level (skill level)
        0,                    // subLevel
        0,                    // sharedReuseGroup
        0,                    // characterType (not used for skills)
        0,                    // enchantLevel (not used for skills)
        0                     // augmentation (not used for skills)
    });
    
    // Health potion shortcut
    shortcuts_.push_back({
        ShortcutType::ITEM,   // type
        1,                    // slot (slot 1, page 0)
        1539,                 // id (item ID for health potion)
        1,                    // level (item count)
        0,                    // subLevel (not used for items)
        0,                    // sharedReuseGroup (not used for items)
        0,                    // characterType (player)
        0,                    // enchantLevel
        0                     // augmentation
    });
    */
} 