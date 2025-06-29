#include "ping_response.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>

PingResponse::PingResponse(const std::vector<uint8_t>& ping_data)
    : ping_data_(ping_data)
{
}

void PingResponse::write(SendablePacketBuffer &buffer)
{
    try
    {
        // Write packet ID (same as received ping)
        buffer.writeUInt8(PACKET_ID);
        
        // Echo back the ping data
        buffer.writeBytes(ping_data_);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error("Failed to write PingResponse packet: " + std::string(e.what()));
    }
}

size_t PingResponse::getSize() const
{
    // Packet ID (1 byte) + ping data length
    return 1 + ping_data_.size();
}

std::string PingResponse::toString() const
{
    std::stringstream ss;
    ss << "PingResponse{data=[";
    for (size_t i = 0; i < ping_data_.size(); ++i) {
        if (i > 0) ss << " ";
        ss << "0x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(ping_data_[i]);
    }
    ss << "]}";
    return ss.str();
} 