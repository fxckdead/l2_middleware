#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <string>

// UserInfo - Server response with player stats, gear, and location
// Critical packet for player spawning - sent after EnterWorld
class UserInfo : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x32; // UserInfo - Interlude Update 3
    const Player* player_;

public:
    // Constructor - create with player data
    explicit UserInfo(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    bool shouldWriteOpcodeAutomatically() const override { return true; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 