#include "auth_gg_response.hpp"
#include <iostream>
#include <iomanip>

// Constructor
AuthGGResponse::AuthGGResponse(int32_t sessionId)
    : m_sessionId(sessionId)
{
}

// SendablePacket interface implementation
uint8_t AuthGGResponse::getPacketId() const
{
    return OPCODE;
}

std::optional<uint16_t> AuthGGResponse::getExPacketId() const
{
    return std::nullopt; // AuthGG response doesn't have extended packet ID
}

void AuthGGResponse::write(SendablePacketBuffer &buffer)
{
    // Write packet structure according to Rust implementation:
    // Opcode + Session ID + 4 zero int32s (GameGuard placeholders) + padding for 4-byte alignment

    buffer.writeUInt8(OPCODE);      // Opcode: 0x0B (GgAuth)
    buffer.writeInt32(m_sessionId); // Session ID: validated session

    // Write 4 zero int32s as GameGuard placeholders
    buffer.writeInt32(0); // GameGuard placeholder 1
    buffer.writeInt32(0); // GameGuard placeholder 2
    buffer.writeInt32(0); // GameGuard placeholder 3
    buffer.writeInt32(0); // GameGuard placeholder 4
}

size_t AuthGGResponse::getSize() const
{
    // Calculate total packet size (without padding):
    // 1 (opcode) + 4 (session_id) + 16 (4 zero int32s) = 21 bytes
    return 1 + 4 + 16;
}

// Factory method
AuthGGResponse AuthGGResponse::create(int32_t sessionId)
{
    return AuthGGResponse(sessionId);
}

// Validate packet data
bool AuthGGResponse::isValid() const
{
    return m_sessionId != 0; // Session ID should be non-zero
}
