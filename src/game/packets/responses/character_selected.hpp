#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <string>

// CharSelected - Server response after successful character selection (RequestGameStart)
// Confirms character selection and provides character data for entering the game world
class CharacterSelected : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x15; // CharacterSelected - Interlude Update 3
    const Player* player_;
    uint32_t sessionId_;

public:
    // Constructor - create with selected character data
    explicit CharacterSelected(const Player* player, uint32_t sessionId);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    bool shouldWriteOpcodeAutomatically() const override { return true; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 