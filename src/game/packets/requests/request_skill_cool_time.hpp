#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

class RequestSkillCoolTime : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x9D;

public:
    RequestSkillCoolTime() = default;

    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;

    bool isValid() const;
}; 