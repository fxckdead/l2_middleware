#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../../core/utils/session_key.hpp"
#include <cstdint>

// Forward declaration
class ReadablePacketBuffer;

// Request to join a specific game server after selecting it from server list
// Matches Rust RequestGSLogin struct from login/src/packet/from_client/request_gs_login.rs
class RequestGSLogin : public ReadablePacket
{
public:
    // Packet ID (matches Rust PACKET_ID = 0x02)
    static constexpr uint8_t PACKET_ID = 0x02;

    // Constructor
    RequestGSLogin();

    // ReadablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void read(ReadablePacketBuffer &buffer) override;

    // Getters for packet data (matches Rust struct fields)
    int32_t getSessionKey1() const { return session_key_1_; }
    int32_t getSessionKey2() const { return session_key_2_; }
    uint8_t getServerId() const { return server_id_; }

    // Session key validation (matches Rust check_session method)
    bool checkSession(const SessionKey &session_key) const;

    // Debug string representation
    std::string toString() const;

private:
    int32_t session_key_1_;    // Session key part 1 (s_key_1 in Rust)
    int32_t session_key_2_;    // Session key part 2 (s_key_2 in Rust)
    uint8_t server_id_;        // Selected server ID
}; 