// src/game/packets/responses/ex_storage_max_count.cpp
#include "ex_storage_max_count.hpp"
#include <iostream>

ExStorageMaxCount::ExStorageMaxCount(const Player* player)
    : player_(player)
{
    if (!player_) {
        throw std::invalid_argument("Player cannot be null for ExStorageMaxCount packet");
    }
    calculateStorageLimits();
}

void ExStorageMaxCount::write(SendablePacketBuffer& buffer)
{
    // Packet structure: 9 storage limits as uint32 values (matches L2J Mobius exactly)
    buffer.writeInt32(static_cast<int32_t>(inventory_));
    buffer.writeInt32(static_cast<int32_t>(warehouse_));
    buffer.writeInt32(static_cast<int32_t>(clan_));
    buffer.writeInt32(static_cast<int32_t>(privateSell_));
    buffer.writeInt32(static_cast<int32_t>(privateBuy_));
    buffer.writeInt32(static_cast<int32_t>(recipeD_));
    buffer.writeInt32(static_cast<int32_t>(recipe_));
    buffer.writeInt32(static_cast<int32_t>(inventoryExtraSlots_)); // Belt inventory slots increase count
    buffer.writeInt32(static_cast<int32_t>(inventoryQuestItems_));
}

size_t ExStorageMaxCount::getSize() const
{
    // Extended opcode (0xFE + 16-bit sub-opcode) + 9 uint32 fields
    return 3 + 36; // 3 bytes opcode + 36 bytes data
}

void ExStorageMaxCount::calculateStorageLimits()
{
    // For now, use default values
    // TODO: Calculate actual limits based on player level, class, and bonuses
    
    inventory_ = 80;              // TODO: player_.getInventoryLimit()
    warehouse_ = 80;              // TODO: player_.getWareHouseLimit()
    clan_ = 200;                  // TODO: Config.WAREHOUSE_SLOTS_CLAN
    privateSell_ = 80;            // TODO: player_.getPrivateSellStoreLimit()
    privateBuy_ = 80;             // TODO: player_.getPrivateBuyStoreLimit()
    recipeD_ = 50;                // TODO: player_.getDwarfRecipeLimit()
    recipe_ = 50;                 // TODO: player_.getCommonRecipeLimit()
    inventoryExtraSlots_ = 0;     // TODO: player_.getStat().calcStat(Stat.INV_LIM, 0, null, null)
    inventoryQuestItems_ = 100;   // TODO: Config.INVENTORY_MAXIMUM_QUEST_ITEMS
    
    // TODO: Implement actual limit calculation
    // Example: inventory_ = 80 + (player_.getLevel() / 10) * 4; // +4 slots per 10 levels
} 