#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

// Client -> server packet (opcode 0x48).
// Mobius reference: gameserver/network/clientpackets/ValidatePosition.java
// Wire layout: 5 x int32 = x, y, z, heading, vehicleId
// vehicleId is read but ignored (no vehicles in scope).
class ValidatePositionPacket : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x48;

public:
    ValidatePositionPacket() = default;

    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void read(ReadablePacketBuffer &buffer) override;

    int32_t getX() const { return m_x; }
    int32_t getY() const { return m_y; }
    int32_t getZ() const { return m_z; }
    int32_t getHeading() const { return m_heading; }

private:
    int32_t m_x = 0;
    int32_t m_y = 0;
    int32_t m_z = 0;
    int32_t m_heading = 0;
    int32_t m_vehicleId = 0; // read + discarded
};
