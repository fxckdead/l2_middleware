#include "login_ok_response.hpp"
#include <iostream>
#include <iomanip>

// Constructor
LoginOkResponse::LoginOkResponse(const SessionKey &sessionKey)
    : m_sessionKey(sessionKey)
{
}

// SendablePacket interface implementation
uint8_t LoginOkResponse::getPacketId() const
{
    return OPCODE;
}

std::optional<uint16_t> LoginOkResponse::getExPacketId() const
{
    return std::nullopt; // LoginOk response doesn't have extended packet ID
}

void LoginOkResponse::write(SendablePacketBuffer &buffer)
{
    // Write packet structure exactly matching Rust implementation:
    // opcode + login_ok1 + login_ok2 + zeros + 0x03ea + zeros + 16 zero bytes

    buffer.writeUInt8(OPCODE);                 // Opcode: 0x03 (LoginOk)
    buffer.writeInt32(m_sessionKey.login_ok1); // Session key part 1
    buffer.writeInt32(m_sessionKey.login_ok2); // Session key part 2
    buffer.writeInt32(0x00);                   // Zero padding
    buffer.writeInt32(0x00);                   // Zero padding
    buffer.writeInt32(0x03ea);                 // Constant 1002 (0x03ea)
    buffer.writeInt32(0x00);                   // Zero padding
    buffer.writeInt32(0x00);                   // Zero padding
    buffer.writeInt32(0x00);                   // Zero padding

    // Write 16 zero bytes (matches Rust: write_bytes(vec![0; 16]))
    for (int i = 0; i < 16; i++)
    {
        buffer.writeUInt8(0x00);
    }
}

size_t LoginOkResponse::getSize() const
{
    // Calculate total packet size (without padding):
    // 1 (opcode) + 4 (login_ok1) + 4 (login_ok2) + 4*6 (zeros/constant) + 16 (zero bytes) = 49 bytes
    return 1 + 4 + 4 + 24 + 16;
}

// Factory method
LoginOkResponse LoginOkResponse::create(const SessionKey &sessionKey)
{
    return LoginOkResponse(sessionKey);
}

// Validate packet data
bool LoginOkResponse::isValid() const
{
    return true; // LoginOk packet is always valid once constructed
}
