#include "new_character_success.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>

NewCharacterSuccess::NewCharacterSuccess()
{
}

void NewCharacterSuccess::write(SendablePacketBuffer &buffer)
{
    try
    {
        buffer.writeUInt8(PACKET_ID);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error("Failed to write PingResponse packet: " + std::string(e.what()));
    }
}

size_t NewCharacterSuccess::getSize() const
{
    // Packet ID (1 byte)
    return 1;
}

std::string NewCharacterSuccess::toString() const
{
    std::stringstream ss;
    ss << "NewCharacterSuccess";
    return ss.str();
}