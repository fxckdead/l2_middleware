#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

// RequestItemList - Client packet requesting inventory item list
// Sent when client opens/closes inventory window
class RequestItemList : public ReadablePacket
{
public:
    // Constructor
    RequestItemList() = default;
    
    // ReadablePacket interface implementation
    void read(ReadablePacketBuffer &buffer) override;
    uint8_t getPacketId() const override { return 0x0F; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    bool isValid() const;
    
    // Getters (if packet contains data)
    std::string toString() const;
}; 