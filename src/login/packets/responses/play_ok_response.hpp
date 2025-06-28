#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../../core/utils/session_key.hpp"
#include <cstdint>
#include <vector>

// Forward declaration
class SendablePacketBuffer;

// Response sent after successful game server selection
// Matches Rust PlayOk packet from login/src/packet/to_client/play_ok.rs
class PlayOkResponse : public SendablePacket
{
public:
    // Packet ID (matches Rust LoginServerOpcodes::PlayOk = 0x07)
    static constexpr uint8_t PACKET_ID = 0x07;

    // Constructor
    explicit PlayOkResponse(const SessionKey &session_key);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;

    // Debug string representation
    std::string toString() const;

private:
    SessionKey session_key_;   // Session key for game server connection
}; 