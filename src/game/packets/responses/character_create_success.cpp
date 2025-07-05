#include "character_create_success.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>

CharacterCreateSuccess::CharacterCreateSuccess()
{
}

void CharacterCreateSuccess::write(SendablePacketBuffer &buffer)
{
    try
    {
        // Opcode is written automatically by base class
        // No additional data needed for this packet
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error("Failed to write CharacterCreateSuccess packet: " + std::string(e.what()));
    }
}

size_t CharacterCreateSuccess::getSize() const
{
    // Packet ID (1 byte)
    return 1;
}

std::string CharacterCreateSuccess::toString() const
{
    std::stringstream ss;
    ss << "CharacterCreateSuccess";
    return ss.str();
} 