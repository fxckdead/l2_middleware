#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

// Client -> server packet (opcode 0x01).
// Mobius reference: gameserver/network/clientpackets/MoveBackwardToLocation.java
// Wire layout: 7 x int32 = targetX, targetY, targetZ, originX, originY, originZ, movementMode
// movementMode == 0 if cursor keys are used, 1 if mouse is used.
class MoveBackwardToLocationPacket : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x01;

public:
    MoveBackwardToLocationPacket() = default;

    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void read(ReadablePacketBuffer &buffer) override;

    int32_t getTargetX() const { return m_targetX; }
    int32_t getTargetY() const { return m_targetY; }
    int32_t getTargetZ() const { return m_targetZ; }
    int32_t getOriginX() const { return m_originX; }
    int32_t getOriginY() const { return m_originY; }
    int32_t getOriginZ() const { return m_originZ; }
    int32_t getMovementMode() const { return m_movementMode; }

private:
    int32_t m_targetX = 0;
    int32_t m_targetY = 0;
    int32_t m_targetZ = 0;
    int32_t m_originX = 0;
    int32_t m_originY = 0;
    int32_t m_originZ = 0;
    int32_t m_movementMode = 0;
};
