// src/game/packets/responses/quest_list.hpp
#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <memory>
#include <vector>

// QuestList packet (opcode 0x80)
// Sends active quests to the client
class QuestList : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x80;
    const Player* player_;
    
    // Quest data structure
    struct QuestData {
        uint32_t questId;
        uint32_t state;  // 1=active, 2=completed, 3=available
    };
    
    std::vector<QuestData> quests_;
    
    void buildQuestList();

public:
    explicit QuestList(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;
}; 