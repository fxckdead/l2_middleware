// src/game/packets/responses/ex_storage_max_count.hpp
#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <memory>

// ExStorageMaxCount packet (opcode 0x2FE)
// Sends inventory and warehouse limits to the client
class ExStorageMaxCount : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xFE;      // Extended packet prefix
    static constexpr uint16_t EX_PACKET_ID = 0x2E;  // Extended packet sub-opcode
    const Player* player_;
    
    // Storage limits (matches L2J Mobius exactly - 9 fields)
    uint32_t inventory_;           // player.getInventoryLimit()
    uint32_t warehouse_;           // player.getWareHouseLimit()
    uint32_t clan_;                // Config.WAREHOUSE_SLOTS_CLAN
    uint32_t privateSell_;         // player.getPrivateSellStoreLimit()
    uint32_t privateBuy_;          // player.getPrivateBuyStoreLimit()
    uint32_t recipeD_;             // player.getDwarfRecipeLimit()
    uint32_t recipe_;              // player.getCommonRecipeLimit()
    uint32_t inventoryExtraSlots_; // player.getStat().calcStat(Stat.INV_LIM, 0, null, null)
    uint32_t inventoryQuestItems_; // Config.INVENTORY_MAXIMUM_QUEST_ITEMS
    
    void calculateStorageLimits();

public:
    explicit ExStorageMaxCount(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    uint16_t getExtendedPacketId() const override { return EX_PACKET_ID; }
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;
}; 