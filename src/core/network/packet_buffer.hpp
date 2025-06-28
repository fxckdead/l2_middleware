#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <optional>

// Forward declarations
class PacketBufferUnderflowException;
class PacketEncodeException;

// ReadablePacketBuffer - equivalent to Rust ReadablePacketBuffer
// Handles reading various data types from a byte buffer with position tracking
class ReadablePacketBuffer
{
private:
    std::vector<uint8_t> m_bytes;
    size_t m_position;

    // Helper method to check buffer bounds and advance position
    void checkAndAdvance(size_t length);

public:
    explicit ReadablePacketBuffer(const std::vector<uint8_t> &bytes);
    explicit ReadablePacketBuffer(std::vector<uint8_t> &&bytes);

    // Basic data type reading (little-endian)
    bool readBoolean();
    uint8_t readByte();
    int8_t readInt8();
    int16_t readInt16();
    uint16_t readUInt16();
    int32_t readInt32();
    uint32_t readUInt32();
    int64_t readInt64();
    uint64_t readUInt64();
    float readFloat32();
    double readFloat64();

    // String reading operations
    std::string readCUtf16leString();                    // C-style null-terminated UTF-16LE string
    std::string readSizedString();                       // Size-prefixed UTF-16LE string
    std::vector<std::string> readNStrings(size_t count); // N null-terminated strings

    // Byte array operations
    std::vector<uint8_t> readBytes(size_t length);
    const uint8_t *readBytesPtr(size_t length); // Returns pointer to internal buffer

    // Buffer status
    size_t getRemainingLength() const;
    size_t getLength() const;
    size_t getPosition() const;

};

// SendablePacketBuffer - equivalent to Rust SendablePacketBuffer
// Handles writing various data types to a byte buffer with automatic size management
class SendablePacketBuffer
{
private:
    std::vector<uint8_t> m_data;
    bool m_sizeWritten;

    // Helper function to ensure capacity
    void ensureCapacity(size_t additionalBytes);

public:
    SendablePacketBuffer();
    explicit SendablePacketBuffer(size_t initialCapacity);

    // Basic data type writing (little-endian)
    void write(uint8_t value);
    void writeInt8(int8_t value);
    void writeUInt8(uint8_t value);
    void writeBoolean(bool value);
    void writeInt16(int16_t value);
    void writeUInt16(uint16_t value);
    void writeInt32(int32_t value);
    void writeUInt32(uint32_t value);
    void writeInt64(int64_t value);
    void writeUInt64(uint64_t value);
    void writeFloat32(float value);
    void writeFloat64(double value);

    // String writing operations
    void writeCUtf16leString(const std::string &value);                     // C-style null-terminated
    void writeCUtf16leString(const std::optional<std::string> &value);      // Optional string
    void writeSizedCUtf16leString(const std::string &value);                // Size-prefixed
    void writeSizedCUtf16leString(const std::optional<std::string> &value); // Optional

    // Byte array operations
    void writeBytes(const std::vector<uint8_t> &bytes);
    void writeBytes(const uint8_t *data, size_t length);

    // Buffer management
    size_t getSize() const;
    void writePacketSize(); // Writes size to first 2 bytes
    void writePadding();    // Adds padding for 8-byte alignment

    // Data access
    std::vector<uint8_t> getData(bool withPadding = false, size_t alignment = 8);
    std::vector<uint8_t> take();                   // Moves data out, finalizes packet
    uint8_t *getDataMut(bool withPadding = false); // Mutable access

private:
    // Helper functions for UTF-16LE encoding
    static std::vector<uint8_t> encodeUtf16le(const std::string &str);
    static std::string decodeUtf16le(const uint8_t *data, size_t length);

    // Little-endian conversion helpers
    static uint16_t bytesToUInt16Le(const uint8_t *bytes);
    static uint32_t bytesToUInt32Le(const uint8_t *bytes);
    static uint64_t bytesToUInt64Le(const uint8_t *bytes);
    static void uint16ToBytesLe(uint16_t value, uint8_t *bytes);
    static void uint32ToBytesLe(uint32_t value, uint8_t *bytes);
    static void uint64ToBytesLe(uint64_t value, uint8_t *bytes);
};