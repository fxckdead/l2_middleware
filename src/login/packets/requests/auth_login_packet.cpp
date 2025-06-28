#include "auth_login_packet.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>

// Constructor
AuthLoginPacket::AuthLoginPacket(const std::string &username, const std::string &password)
    : m_username(username), m_password(password), m_isNewAuth(false)
{
}

// ReadablePacket interface implementation
uint8_t AuthLoginPacket::getPacketId() const
{
    return OPCODE;
}

std::optional<uint16_t> AuthLoginPacket::getExPacketId() const
{
    return std::nullopt;
}

void AuthLoginPacket::read(ReadablePacketBuffer &buffer)
{
    // This method would be used for reading from network buffer
    // For RSA decrypted data, use fromRsaDecryptedData instead
    throw PacketException("AuthLoginPacket::read() not implemented - use fromRsaDecryptedData()");
}

// Factory method for RSA decrypted data (primary use case)
AuthLoginPacket AuthLoginPacket::fromRsaDecryptedData(const std::vector<uint8_t> &decryptedData)
{
    auto [username, password] = extractCredentials(decryptedData);

    AuthLoginPacket packet(username, password);
    packet.m_isNewAuth = decryptedData.size() >= 256;

    return packet;
}

// Extract credentials from raw decrypted bytes (matches Rust read_bytes function)
std::pair<std::string, std::string> AuthLoginPacket::extractCredentials(const std::vector<uint8_t> &data)
{
    bool isNewAuth = data.size() >= 256;
    std::string username;
    std::string password;

    if (isNewAuth)
    {
        // New auth format (256 bytes)
        // Username is split into two parts: 0x4E + 0xCE
        std::string part1 = extractStringFromBytes(data, 0x4E, 50); // 0x4E..0x4E+50
        std::string part2 = extractStringFromBytes(data, 0xCE, 14); // 0xCE..0xCE+14

        username = trimNullBytes(part1) + trimNullBytes(part2);
        password = trimNullBytes(extractStringFromBytes(data, 0xDC, 16)); // 0xDC..0xDC+16
    }
    else
    {
        // Old auth format (128 bytes)
        username = trimNullBytes(extractStringFromBytes(data, 0x5E, 14)); // 0x5E..0x5E+14
        password = trimNullBytes(extractStringFromBytes(data, 0x6C, 16)); // 0x6C..0x6C+16
    }

    return std::make_pair(username, password);
}

// Validation
bool AuthLoginPacket::isValid() const
{
    return !m_username.empty() && !m_password.empty() &&
           m_username.length() <= 64 && m_password.length() <= 32;
}

// Helper functions for credential extraction
std::string AuthLoginPacket::extractStringFromBytes(const std::vector<uint8_t> &data,
                                                    size_t offset, size_t maxLength)
{
    if (offset >= data.size())
    {
        return "";
    }

    size_t endPos = std::min(offset + maxLength, data.size());
    std::string result;
    result.reserve(maxLength);

    // Extract bytes as string (assuming UTF-8/ASCII encoding)
    for (size_t i = offset; i < endPos; ++i)
    {
        if (data[i] == 0)
        {
            break; // Stop at null terminator
        }
        result += static_cast<char>(data[i]);
    }

    return result;
}

std::string AuthLoginPacket::trimNullBytes(const std::string &str)
{
    // Remove null bytes and whitespace from both ends
    size_t start = 0;
    size_t end = str.length();

    // Find first non-null, non-whitespace character
    while (start < end && (str[start] == '\0' || std::isspace(str[start])))
    {
        ++start;
    }

    // Find last non-null, non-whitespace character
    while (end > start && (str[end - 1] == '\0' || std::isspace(str[end - 1])))
    {
        --end;
    }

    return str.substr(start, end - start);
}

