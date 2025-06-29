#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

class ProtocolVersionPacket : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x0E;
    int32_t client_protocol_version_ = 0;

public:
    ProtocolVersionPacket() = default;

    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;
    bool isValid() const;
    
    // Getter for protocol version
    int32_t getClientProtocolVersion() const { return client_protocol_version_; }
};