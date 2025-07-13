#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

// RequestShowMiniMap - Client packet requesting minimap display (0xCD)
// Simple request packet with no additional data to read
class RequestShowMiniMap : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xCD;

public:
    RequestShowMiniMap() = default;

    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;

    bool isValid() const;
}; 