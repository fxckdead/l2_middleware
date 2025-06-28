#include "request_auth_gg.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>

// Constructor
RequestAuthGG::RequestAuthGG(int32_t sessionId)
    : m_sessionId(sessionId)
{
}

// ReadablePacket interface implementation
uint8_t RequestAuthGG::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> RequestAuthGG::getExPacketId() const
{
    return std::nullopt;
}

void RequestAuthGG::read(ReadablePacketBuffer &buffer)
{
    // Read session ID from the buffer (first 4 bytes)
    if (buffer.getRemainingLength() >= 4)
    {
        m_sessionId = buffer.readInt32();
        // Note: Remaining bytes are GameGuard data that we ignore for now
        // The Rust implementation mentions they don't know the meaning of the remaining data
    }
    else
    {
        throw PacketException("Not enough data for RequestAuthGG packet");
    }
}

// Factory method for raw data (matches Rust read implementation)
RequestAuthGG RequestAuthGG::fromRawData(const std::vector<uint8_t> &data)
{
    if (data.size() < 4)
    {
        throw PacketException("Not enough data for AuthGG packet - need at least 4 bytes for session ID");
    }

    // Rust implementation checks for > 20 bytes, but we'll be more flexible
    int32_t sessionId = extractSessionId(data);

    return RequestAuthGG(sessionId);
}

// Extract session ID from raw bytes (first 4 bytes, little-endian)
int32_t RequestAuthGG::extractSessionId(const std::vector<uint8_t> &data)
{
    if (data.size() < 4)
    {
        throw PacketException("Insufficient data for session ID extraction");
    }

    // Little-endian conversion (matches your existing pattern)
    return static_cast<int32_t>(data[0]) |
           (static_cast<int32_t>(data[1]) << 8) |
           (static_cast<int32_t>(data[2]) << 16) |
           (static_cast<int32_t>(data[3]) << 24);
}

// Validation
bool RequestAuthGG::isValid() const
{
    // Session ID should be non-zero (basic validation)
    return m_sessionId != 0;
}
