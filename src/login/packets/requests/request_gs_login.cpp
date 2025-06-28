#include "request_gs_login.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <stdexcept>

RequestGSLogin::RequestGSLogin()
    : session_key_1_(0), session_key_2_(0), server_id_(0)
{
}

void RequestGSLogin::read(ReadablePacketBuffer &buffer)
{
    try
    {
        // Read packet data (matches Rust read() implementation)
        // Packet structure: [s_key_1: i32][s_key_2: i32][server_id: u8]
        session_key_1_ = buffer.readInt32();
        session_key_2_ = buffer.readInt32();
        server_id_ = buffer.readByte();
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error("Failed to read RequestGSLogin packet: " + std::string(e.what()));
    }
}

bool RequestGSLogin::checkSession(const SessionKey &session_key) const
{
    // Matches Rust check_session implementation
    // Validates session key parts against stored session
    return session_key.check_session(session_key_1_, session_key_2_);
}

std::string RequestGSLogin::toString() const
{
    return "RequestGSLogin{session_key_1=" + std::to_string(session_key_1_) +
           ", session_key_2=" + std::to_string(session_key_2_) +
           ", server_id=" + std::to_string(server_id_) + "}";
} 