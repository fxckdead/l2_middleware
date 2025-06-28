#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

// RequestServerList - Handles client request for server list (opcode 0x05)
// Matches RequestServerList from Rust implementation
// This packet is sent by client after successful authentication to get available game servers
class RequestServerList : public ReadablePacket
{
private:
    static constexpr uint8_t OPCODE = 0x05;

    // Data fields from the packet (matches Rust struct)
    int32_t m_loginOk1;
    int32_t m_loginOk2;

public:
    RequestServerList() = default;
    explicit RequestServerList(int32_t loginOk1, int32_t loginOk2);

    // ReadablePacket interface implementation
    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;

    // Validation
    bool isValid() const;

    // Accessors
    int32_t getLoginOk1() const { return m_loginOk1; }
    int32_t getLoginOk2() const { return m_loginOk2; }

    // Factory method
    static RequestServerList create(int32_t loginOk1, int32_t loginOk2);
}; 