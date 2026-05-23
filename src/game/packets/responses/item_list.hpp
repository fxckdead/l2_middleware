#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <vector>

// ItemList - Server response with player inventory contents
// Shows all items in player's inventory
class ItemList : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x1B; // ItemList - Interlude Update 3 (FIXED: was 0x11=BuyList)
    const Player* player_;
    bool show_window_; // Whether to show inventory window

public:
    // Constructor - create with player data
    explicit ItemList(const Player* player, bool showWindow = false);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 