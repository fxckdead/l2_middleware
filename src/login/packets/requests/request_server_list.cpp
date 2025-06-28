#include "request_server_list.hpp"

// Constructor
RequestServerList::RequestServerList(int32_t loginOk1, int32_t loginOk2)
    : m_loginOk1(loginOk1), m_loginOk2(loginOk2)
{
}

// ReadablePacket interface implementation
uint8_t RequestServerList::getPacketId() const
{
    return OPCODE;
}

std::optional<uint16_t> RequestServerList::getExPacketId() const
{
    return std::nullopt; // RequestServerList doesn't have extended packet ID
}

void RequestServerList::read(ReadablePacketBuffer &buffer)
{
    // Read packet structure exactly matching Rust implementation:
    // The opcode is already consumed by the packet factory
    // Read the two i32 fields
    m_loginOk1 = buffer.readInt32();
    m_loginOk2 = buffer.readInt32();
}

// Validation
bool RequestServerList::isValid() const
{
    // RequestServerList is always valid once the fields are read
    return true;
}

// Factory method
RequestServerList RequestServerList::create(int32_t loginOk1, int32_t loginOk2)
{
    return RequestServerList(loginOk1, loginOk2);
} 