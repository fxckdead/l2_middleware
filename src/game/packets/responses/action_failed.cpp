#include "action_failed.hpp"
#include <iostream>

// Constructor
ActionFailed::ActionFailed()
{
}

void ActionFailed::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class
    // No additional data needed for this packet (matches L2J Mobius exactly)

    std::cout << "[ActionFailed] Sending action completion signal" << std::endl;
}

size_t ActionFailed::getSize() const
{
    // Packet ID only (1 byte)
    return 1;
} 