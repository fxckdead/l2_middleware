#pragma once

#include <vector>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <optional>

// Forward declarations
class ReadablePacketBuffer;
class SendablePacketBuffer;

// Exception classes for packet operations
class PacketException : public std::runtime_error
{
public:
    explicit PacketException(const std::string &message) : std::runtime_error(message) {}
};

class PacketBufferUnderflowException : public PacketException
{
public:
    explicit PacketBufferUnderflowException(const std::string &message)
        : PacketException("Buffer underflow: " + message) {}
};

class PacketEncodeException : public PacketException
{
public:
    explicit PacketEncodeException(const std::string &encoding)
        : PacketException("Encoding error: " + encoding) {}
};

// Base interface for readable packets (equivalent to Rust ReadablePacket trait)
class ReadablePacket
{
public:
    virtual ~ReadablePacket() = default;

    // Packet identification
    virtual uint8_t getPacketId() const = 0;
    virtual std::optional<uint16_t> getExPacketId() const = 0;

    // Read packet data from buffer
    virtual void read(ReadablePacketBuffer &buffer) = 0;

    // Factory method for creating packets from raw data
    static std::unique_ptr<ReadablePacket> createFromData(const std::vector<uint8_t> &data);
};

// Base interface for sendable packets
class SendablePacket
{
public:
    virtual ~SendablePacket() = default;

    // Packet identification
    virtual uint8_t getPacketId() const = 0;
    virtual std::optional<uint16_t> getExPacketId() const = 0;

    // Write packet data to buffer
    virtual void write(SendablePacketBuffer &buffer) = 0;

    // Get serialized packet data
    virtual std::vector<uint8_t> serialize(bool withPadding = false);
    virtual std::vector<uint8_t> serialize(bool withPadding, size_t alignment);

    // Get packet size
    virtual size_t getSize() const = 0;
};

// Common opcodes for different packet directions
enum class LoginServerOpcode : uint8_t
{
    Init = 0x00,
    LoginFail = 0x01,
    AccountKicked = 0x02,
    LoginOk = 0x03,
    ServerList = 0x04,
    PlayFail = 0x05,
    PlayOk = 0x07,
    GgAuth = 0x0B
};

enum class GameServerOpcode : uint8_t
{
    RequestAuthGS = 0x01,
    BlowfishKey = 0x00,
    PlayerAuthRequest = 0x05
};

enum class ClientOpcode : uint8_t
{
    RequestAuthLogin = 0x00,
    RequestServerLogin = 0x02,
    RequestServerList = 0x05,
    RequestAuthGG = 0x07
};

// Utility functions for packet operations
namespace PacketUtils
{
    // Calculate packet size with padding
    size_t calculatePaddedSize(size_t dataSize);

    // Add padding to packet data for 8-byte alignment (Blowfish requirement)
    void addPadding(std::vector<uint8_t> &data);

    // Test functions
    void runTests();
}