#include "move_backward_to_location_packet.hpp"

void MoveBackwardToLocationPacket::read(ReadablePacketBuffer &buffer)
{
    m_targetX = buffer.readInt32();
    m_targetY = buffer.readInt32();
    m_targetZ = buffer.readInt32();
    m_originX = buffer.readInt32();
    m_originY = buffer.readInt32();
    m_originZ = buffer.readInt32();
    m_movementMode = buffer.readInt32();
}
