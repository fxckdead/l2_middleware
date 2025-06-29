#include "version_check_response.hpp"
#include <sstream>
#include <iomanip>
#include <stdexcept>

// Constructor
VersionCheckResponse::VersionCheckResponse(bool protocol_ok)
    : protocol_ok_(protocol_ok), opcode_obfuscation_key_(0)
{
    // Default dynamic key (will be overridden by proper constructor)
    dynamic_key_ = {0x94, 0x35, 0x00, 0x00, 0xa1, 0x6c, 0x54, 0x87, 
                    0x45, 0xa3, 0x7a, 0x86, 0xf0, 0x33, 0x40, 0x64};
}

// Constructor with explicit key and obfuscation
VersionCheckResponse::VersionCheckResponse(bool protocol_ok, const std::vector<uint8_t>& dynamic_key, uint32_t obfuscation_key)
    : protocol_ok_(protocol_ok), dynamic_key_(dynamic_key), opcode_obfuscation_key_(obfuscation_key)
{
}

void VersionCheckResponse::write(SendablePacketBuffer &buffer)
{
    // Write VersionCheck packet structure for Interlude Update 3
    // According to protocol: must include dynamic key and opcode obfuscation key
    
    buffer.writeUInt8(PACKET_ID);  // Opcode: 0x00 (VersionCheck)
    
    if (protocol_ok_) {
        // Protocol accepted flag (1 byte)
        buffer.writeUInt8(0x01);

        // 16-byte Blowfish key
        if (dynamic_key_.size() != 16) {
            throw std::runtime_error("Dynamic key must be 16 bytes");
        }
        buffer.writeBytes(dynamic_key_);

        // 4-byte opcode obfuscation key (usually zero)
        buffer.writeUInt32(opcode_obfuscation_key_);

        // 4-byte feature flags mask (0x00000300 for Interlude without GG)
        buffer.writeUInt32(feature_flags_);

        // Reserved byte (always 0)
        buffer.writeUInt8(reserved_);
    } else {
        // Protocol rejected – send single 0x00 flag instead of 0x01
        buffer.writeUInt8(0x00);
    }
}

size_t VersionCheckResponse::getSize() const
{
    if (protocol_ok_) {
        // 1 (opcode) + 1 (flag) + 16 (key) + 4 (obfs) + 4 (features) + 1 (reserved) = 27 bytes
        return 27;
    } else {
        // 1 (opcode) + 1 (flag) = 2 bytes
        return 2;
    }
}

std::string VersionCheckResponse::toString() const
{
    std::stringstream ss;
    ss << "VersionCheckResponse{protocol_ok=" << (protocol_ok_ ? "true" : "false") << "}";
    return ss.str();
} 