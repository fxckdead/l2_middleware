#pragma once

#include "packet.hpp"
#include "packet_buffer.hpp"
#include <vector>
#include <cstdint>

// AuthGGResponse - Response packet for GameGuard authentication
// Matches AuthGG from Rust implementation (opcode 0x0B)
// Sent in response to RequestAuthGG to validate the client session
class AuthGGResponse : public SendablePacket
{
private:
    static constexpr uint8_t OPCODE = 0x0B; // LoginServerOpcodes::GgAuth

    int32_t m_sessionId;

public:
    // Constructor
    explicit AuthGGResponse(int32_t sessionId);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;

    // Accessors
    int32_t getSessionId() const { return m_sessionId; }

    // Factory method
    static AuthGGResponse create(int32_t sessionId);

    // Test function
    static void runTests();

private:
    // Validate packet data
    bool isValid() const;
};