#include "move_to_location.hpp"
#include <iostream>

// Constructor
MoveToLocation::MoveToLocation(const Player* player)
    : m_objectId(0),
      m_x(0), m_y(0), m_z(0),
      m_xDst(0), m_yDst(0), m_zDst(0)
{
    if (!player)
    {
        throw std::invalid_argument("Player cannot be null for MoveToLocation packet");
    }
    m_objectId = player->getObjectId();
    m_x = player->getX();
    m_y = player->getY();
    m_z = player->getZ();
    m_xDst = player->getDestX();
    m_yDst = player->getDestY();
    m_zDst = player->getDestZ();
}

void MoveToLocation::write(SendablePacketBuffer& buffer)
{
    // Opcode is written automatically by base class
    
    std::cout << "[MoveToLocation] Sending movement for object ID: " << m_objectId 
              << " from (" << m_x << ", " << m_y << ", " << m_z << ")"
              << " to (" << m_xDst << ", " << m_yDst << ", " << m_zDst << ")" << std::endl;
    
    // Following L2J Mobius MoveToLocation.java structure EXACTLY
    
    // 1. Object ID
    buffer.writeUInt32(m_objectId);
    
    // 2. Destination coordinates
    buffer.writeUInt32(m_xDst);
    buffer.writeUInt32(m_yDst);
    buffer.writeUInt32(m_zDst);
    
    // 3. Current coordinates
    buffer.writeUInt32(m_x);
    buffer.writeUInt32(m_y);
    buffer.writeUInt32(m_z);
}

size_t MoveToLocation::getSize() const
{
    // Packet ID (1) + objectId (4) + xDst (4) + yDst (4) + zDst (4) + x (4) + y (4) + z (4) = 29 bytes
    return 29;
} 