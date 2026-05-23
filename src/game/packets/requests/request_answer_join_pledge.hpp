#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

class RequestAnswerJoinPledge : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x25;
    
    // Pledge join response data
    uint32_t response_ = 0; // 0 = decline, 1 = accept

public:
    RequestAnswerJoinPledge() = default;

    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;

    bool isValid() const;
    
    // Getters for pledge response data
    uint32_t getResponse() const { return response_; }
}; 