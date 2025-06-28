#include "server_data.hpp"
#include <sstream>
#include <regex>

// ServerData constructor
ServerData::ServerData(const std::string& ip, int32_t port, int32_t ageLimit, bool pvp,
                      int32_t currentPlayers, int32_t maxPlayers, bool brackets,
                      bool clock, std::optional<ServerStatus> status, int32_t serverId,
                      std::optional<ServerType> serverType)
    : ip(ip), port(port), ageLimit(ageLimit), pvp(pvp), currentPlayers(currentPlayers),
      maxPlayers(maxPlayers), brackets(brackets), clock(clock), status(status),
      serverId(serverId), serverType(serverType)
{
}

// Get IP address as 4 octets array
std::array<uint8_t, 4> ServerData::getIpOctets() const
{
    std::array<uint8_t, 4> octets = {0, 0, 0, 0};
    
    // Parse IP address string into octets
    std::istringstream ss(ip);
    std::string octet;
    int index = 0;
    
    while (std::getline(ss, octet, '.') && index < 4)
    {
        try
        {
            int value = std::stoi(octet);
            if (value >= 0 && value <= 255)
            {
                octets[index] = static_cast<uint8_t>(value);
            }
            index++;
        }
        catch (const std::exception&)
        {
            // Invalid octet, keep default value (0)
        }
    }
    
    return octets;
}

// Validation
bool ServerData::isValid() const
{
    // Validate IP address format
    std::regex ipRegex(R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
    if (!std::regex_match(ip, ipRegex))
    {
        return false;
    }
    
    // Validate port range
    if (port < 1 || port > 65535)
    {
        return false;
    }
    
    // Validate age limit
    if (ageLimit < 0 || ageLimit > 255)
    {
        return false;
    }
    
    // Validate player counts
    if (currentPlayers < 0 || maxPlayers < 0 || currentPlayers > maxPlayers)
    {
        return false;
    }
    
    return true;
} 