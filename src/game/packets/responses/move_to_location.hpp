#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>

// MoveToLocation - Server response showing creature movement
// Tells the client that a creature is moving from current position to destination
// Based on L2J Mobius MoveToLocation.java implementation
class MoveToLocation : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x01; // MoveToLocation - Interlude Update 3
    uint32_t m_objectId;
    uint32_t m_x;
    uint32_t m_y;
    uint32_t m_z;
    uint32_t m_xDst;
    uint32_t m_yDst;
    uint32_t m_zDst;

public:
    // Constructor - create with creature data
    explicit MoveToLocation(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;
}; 