#include "play_ok_response.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <stdexcept>

PlayOkResponse::PlayOkResponse(const SessionKey &session_key)
    : session_key_(session_key)
{
}

void PlayOkResponse::write(SendablePacketBuffer &buffer)
{
    try
    {
        // Write packet ID (matches Rust LoginServerOpcodes::PlayOk = 0x07)
        buffer.writeUInt8(PACKET_ID);
        
        // Write session key for game server connection (matches Rust PlayOk::new implementation)
        // The client will use these values to authenticate with the game server
        buffer.writeInt32(session_key_.play_ok1);
        buffer.writeInt32(session_key_.play_ok2);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error("Failed to write PlayOkResponse packet: " + std::string(e.what()));
    }
}

size_t PlayOkResponse::getSize() const
{
    // Packet ID (1 byte) + play_ok1 (4 bytes) + play_ok2 (4 bytes) = 9 bytes total
    return 9;
}

std::string PlayOkResponse::toString() const
{
    return "PlayOkResponse{play_ok1=" + std::to_string(session_key_.play_ok1) +
           ", play_ok2=" + std::to_string(session_key_.play_ok2) + "}";
} 