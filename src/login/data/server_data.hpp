#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <array>

// Server status enumeration (matches Rust ServerStatus)
enum class ServerStatus : uint8_t
{
    Auto = 0x00,
    Good = 0x01,
    Normal = 0x02,
    Full = 0x03,
    Down = 0x04,
    GmOnly = 0x05
};

// Server type enumeration (matches Rust ServerType)
enum class ServerType : int32_t
{
    Normal = 0x01,
    Relax = 0x02,
    Test = 0x04,
    NoLabel = 0x08,
    CreationRestricted = 0x10,
    Event = 0x20,
    Free = 0x40
};

// Structure representing server data sent to client (matches Rust ServerData)
struct ServerData
{
    std::string ip;                                 // IPv4 address as string
    int32_t port;                                   // Server port
    int32_t ageLimit;                               // Age limit (0, 15, 18)
    bool pvp;                                       // PvP enabled flag
    int32_t currentPlayers;                         // Current player count
    int32_t maxPlayers;                             // Maximum players
    bool brackets;                                  // Show brackets around server name
    bool clock;                                     // Show clock (not used in current implementation)
    std::optional<ServerStatus> status;             // Server status
    int32_t serverId;                               // Server ID
    std::optional<ServerType> serverType;           // Server type

    // Constructor
    ServerData() = default;
    ServerData(const std::string& ip, int32_t port, int32_t ageLimit, bool pvp,
              int32_t currentPlayers, int32_t maxPlayers, bool brackets,
              bool clock, std::optional<ServerStatus> status, int32_t serverId,
              std::optional<ServerType> serverType);

    // Get IP address as 4 octets array
    std::array<uint8_t, 4> getIpOctets() const;

    // Validation
    bool isValid() const;
};

// Structure for character information per server (matches Rust GSCharsInfo)
struct GSCharsInfo
{
    uint8_t totalChars;

    GSCharsInfo() : totalChars(0) {}
    explicit GSCharsInfo(uint8_t chars) : totalChars(chars) {}
}; 