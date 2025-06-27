#pragma once

#include "packet.hpp"
#include "packet_buffer.hpp"
#include <string>
#include <vector>
#include <cstdint>

// AuthLoginPacket - Handles RSA-encrypted login credentials from clients
// Matches RequestAuthLogin from Rust implementation
// This packet receives RSA-decrypted data containing username/password
class AuthLoginPacket : public ReadablePacket
{
private:
    static constexpr uint8_t OPCODE = 0x00;

    // Extracted credentials
    std::string m_username;
    std::string m_password;

    // Format detection
    bool m_isNewAuth; // true for 256-byte format, false for 128-byte format

public:
    AuthLoginPacket() = default;
    explicit AuthLoginPacket(const std::string &username, const std::string &password);

    // ReadablePacket interface implementation
    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;

    // Factory method for RSA decrypted data (primary use case)
    static AuthLoginPacket fromRsaDecryptedData(const std::vector<uint8_t> &decryptedData);

    // Extract credentials from raw decrypted bytes (matches Rust read_bytes function)
    static std::pair<std::string, std::string> extractCredentials(const std::vector<uint8_t> &data);

    // Validation
    bool isValid() const;

    // Accessors
    const std::string &getUsername() const { return m_username; }
    const std::string &getPassword() const { return m_password; }
    bool isNewAuthFormat() const { return m_isNewAuth; }

    // Test function
    static void runTests();

    // Demo function showing L2 authentication flow
    static void demoL2AuthFlow();

    // Debug function to verify Rust test data positions
    static void debugRustTestData();

private:
    // Helper functions for credential extraction
    static std::string extractStringFromBytes(const std::vector<uint8_t> &data,
                                              size_t offset, size_t maxLength);
    static std::string trimNullBytes(const std::string &str);
};