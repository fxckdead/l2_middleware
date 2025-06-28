#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <string>
#include <vector>
#include <cstdint>

// RequestAuthGG - Handles GameGuard authentication packets from clients
// Matches RequestAuthGG from Rust implementation (packet ID 0x07)
// This packet receives GameGuard data containing session ID validation
class RequestAuthGG : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x07;

    // Session ID from client (first 4 bytes)
    int32_t m_sessionId;

public:
    RequestAuthGG() = default;
    explicit RequestAuthGG(int32_t sessionId);

    // ReadablePacket interface implementation
    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;

    // Factory method for creating from raw data
    static RequestAuthGG fromRawData(const std::vector<uint8_t> &data);

    // Validation
    bool isValid() const;

    // Accessors
    int32_t getSessionId() const { return m_sessionId; }

    // Test function

private:
    // Helper functions
    static int32_t extractSessionId(const std::vector<uint8_t> &data);
};