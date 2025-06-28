#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../../core/utils/session_key.hpp"
#include <vector>
#include <cstdint>

// LoginOk - Response packet sent after successful authentication
// Matches LoginOk from Rust implementation (opcode 0x03)
// Contains session keys that client needs for further communication
class LoginOkResponse : public SendablePacket
{
private:
    static constexpr uint8_t OPCODE = 0x03; // LoginServerOpcodes::LoginOk

    SessionKey m_sessionKey;

public:
    // Constructor
    explicit LoginOkResponse(const SessionKey &sessionKey);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;

    // Accessors
    const SessionKey &getSessionKey() const { return m_sessionKey; }

    // Factory method
    static LoginOkResponse create(const SessionKey &sessionKey);

    // Validate packet data
    bool isValid() const;

    // Test function

private:
};