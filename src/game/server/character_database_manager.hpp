#pragma once

#include "../packets/responses/character_selection_info.hpp"
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>
#include <cstdint>
#include <optional>
#include <atomic>

// CharacterDatabaseManager - Manages character data in memory
// Provides thread-safe CRUD operations for character storage
// Follows the same pattern as GameServerManager
class CharacterDatabaseManager
{
private:
    std::unordered_map<uint32_t, CharacterInfo> m_characters;                   // Character ID -> Character data
    std::unordered_map<std::string, std::vector<uint32_t>> m_accountCharacters; // Account -> Character IDs
    mutable std::mutex m_charactersMutex;                                       // Thread safety for character operations
    std::atomic<uint32_t> m_nextCharacterId{1};                                 // Auto-incrementing character ID

public:
    CharacterDatabaseManager() = default;
    ~CharacterDatabaseManager() = default;

    // Disable copy operations for thread safety
    CharacterDatabaseManager(const CharacterDatabaseManager &) = delete;
    CharacterDatabaseManager &operator=(const CharacterDatabaseManager &) = delete;

    // Character creation and management
    uint32_t createCharacter(const std::string &accountName, const std::string &characterName,
                             uint32_t race, uint32_t sex, uint32_t classId,
                             uint32_t hairStyle = 0, uint32_t hairColor = 0, uint32_t face = 0);

    bool deleteCharacter(uint32_t characterId, const std::string &accountName);
    bool characterExists(const std::string &characterName) const;
    bool isValidCharacterName(const std::string &name) const;

    // Character retrieval
    std::optional<CharacterInfo> getCharacterById(uint32_t characterId) const;
    std::optional<CharacterInfo> getCharacterBySlot(const std::string &accountName, uint32_t slotIndex) const;
    std::optional<CharacterInfo> getCharacterByName(const std::string &characterName) const;
    std::vector<CharacterInfo> getCharactersForAccount(const std::string &accountName) const;

    // Character information
    size_t getCharacterCount() const;
    size_t getCharacterCountForAccount(const std::string &accountName) const;

    // Validation and utility methods
    bool isValidCharacterId(uint32_t characterId) const;
    void clearAllCharacters();

    // Character updates (for future expansion)
    bool updateCharacterLevel(uint32_t characterId, uint32_t newLevel);
    bool updateCharacterPosition(uint32_t characterId, uint32_t x, uint32_t y, uint32_t z);

    // For testing and debugging
    std::vector<uint32_t> getAllCharacterIds() const;
    std::vector<std::string> getAllAccountNames() const;

private:
    // Helper methods
    uint32_t generateNextCharacterId();
    CharacterInfo createDefaultCharacter(const std::string &accountName, const std::string &characterName,
                                         uint32_t race, uint32_t sex, uint32_t classId,
                                         uint32_t hairStyle, uint32_t hairColor, uint32_t face);
    void addCharacterToAccount(const std::string &accountName, uint32_t characterId);
    void removeCharacterFromAccount(const std::string &accountName, uint32_t characterId);
};