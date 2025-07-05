#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <vector>

// HennaInfo - Server response with active henna (dye) information
// Shows equipped henna dyes and their stat bonuses
class HennaInfo : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xE4; // HennaInfo - Interlude Update 3
    const Player* player_;
    
    // Henna data structure (matches L2J Mobius)
    struct HennaData {
        uint32_t dyeId;
        uint32_t count;
    };
    
    std::vector<HennaData> hennas_;
    
    void buildHennaList();

public:
    // Constructor - create with player data
    explicit HennaInfo(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 