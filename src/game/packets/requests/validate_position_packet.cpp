#include "validate_position_packet.hpp"

void ValidatePositionPacket::read(ReadablePacketBuffer &buffer)
{
    m_x = buffer.readInt32();
    m_y = buffer.readInt32();
    m_z = buffer.readInt32();
    m_heading = buffer.readInt32();
    m_vehicleId = buffer.readInt32(); // discarded
}
