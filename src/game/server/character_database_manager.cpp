#include "character_database_manager.hpp"
#include <algorithm>
#include <stdexcept>
#include <regex>
#include <iostream>

// Character creation and management
uint32_t CharacterDatabaseManager::createCharacter(const std::string &accountName, const std::string &characterName,
                                                   uint32_t race, uint32_t sex, uint32_t classId,
                                                   uint32_t hairStyle, uint32_t hairColor, uint32_t face)
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    // Validate character name
    if (!isValidCharacterName(characterName))
    {
        return 0; // Invalid character name
    }

    // Check if character name already exists
    for (const auto &[charId, character] : m_characters)
    {
        if (character.name == characterName)
        {
            return 0; // Character name already exists
        }
    }

    // Check account character limit (max 7 characters per account in L2)
    auto accountCharIter = m_accountCharacters.find(accountName);
    if (accountCharIter != m_accountCharacters.end() && accountCharIter->second.size() >= 7)
    {
        return 0; // Account has too many characters
    }

    // Generate character ID and create character
    uint32_t characterId = generateNextCharacterId();
    CharacterInfo newCharacter = createDefaultCharacter(accountName, characterName, race, sex, classId,
                                                        hairStyle, hairColor, face);
    newCharacter.char_id = characterId;

    // Store character and update account mapping
    m_characters[characterId] = newCharacter;
    addCharacterToAccount(accountName, characterId);

    return characterId;
}

bool CharacterDatabaseManager::deleteCharacter(uint32_t characterId, const std::string &accountName)
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    auto charIter = m_characters.find(characterId);
    if (charIter == m_characters.end())
    {
        return false; // Character not found
    }

    // Verify the character belongs to this account
    if (charIter->second.login_name != accountName)
    {
        return false; // Character doesn't belong to this account
    }

    // Remove character from storage and account mapping
    m_characters.erase(charIter);
    removeCharacterFromAccount(accountName, characterId);

    return true;
}

bool CharacterDatabaseManager::characterExists(const std::string &characterName) const
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    for (const auto &[charId, character] : m_characters)
    {
        if (character.name == characterName)
        {
            return true;
        }
    }

    return false;
}

bool CharacterDatabaseManager::isValidCharacterName(const std::string &name) const
{
    // Basic validation for L2 character names
    if (name.empty() || name.length() > 16 || name.length() < 3)
    {
        return false;
    }

    // Check for valid characters (letters and numbers, no special chars)
    std::regex validName("^[a-zA-Z][a-zA-Z0-9]*$");
    return std::regex_match(name, validName);
}

// Character retrieval
std::optional<CharacterInfo> CharacterDatabaseManager::getCharacterById(uint32_t characterId) const
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    auto it = m_characters.find(characterId);
    if (it != m_characters.end())
    {
        return it->second;
    }

    return std::nullopt;
}

std::optional<CharacterInfo> CharacterDatabaseManager::getCharacterBySlot(const std::string &accountName, uint32_t slotIndex) const
{
    auto characters = getCharactersForAccount(accountName);

    if (slotIndex < characters.size())
    {
        return characters[slotIndex];
    }

    return std::nullopt;
}

std::optional<CharacterInfo> CharacterDatabaseManager::getCharacterByName(const std::string &characterName) const
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    for (const auto &[charId, character] : m_characters)
    {
        if (character.name == characterName)
        {
            return character;
        }
    }

    return std::nullopt;
}

std::vector<CharacterInfo> CharacterDatabaseManager::getCharactersForAccount(const std::string &accountName) const
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    std::vector<CharacterInfo> accountCharacters;

    auto accountIter = m_accountCharacters.find(accountName);
    if (accountIter != m_accountCharacters.end())
    {
        accountCharacters.reserve(accountIter->second.size());

        for (uint32_t characterId : accountIter->second)
        {
            auto charIter = m_characters.find(characterId);
            if (charIter != m_characters.end())
            {
                accountCharacters.push_back(charIter->second);
            }
        }
    }

    // Sort by character ID for consistent ordering
    std::sort(accountCharacters.begin(), accountCharacters.end(),
              [](const CharacterInfo &a, const CharacterInfo &b)
              {
                  return a.char_id < b.char_id;
              });

    return accountCharacters;
}

// Character information
size_t CharacterDatabaseManager::getCharacterCount() const
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);
    return m_characters.size();
}

size_t CharacterDatabaseManager::getCharacterCountForAccount(const std::string &accountName) const
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    auto accountIter = m_accountCharacters.find(accountName);
    if (accountIter != m_accountCharacters.end())
    {
        return accountIter->second.size();
    }

    return 0;
}

// Validation and utility methods
bool CharacterDatabaseManager::isValidCharacterId(uint32_t characterId) const
{
    return characterId > 0;
}

void CharacterDatabaseManager::clearAllCharacters()
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);
    m_characters.clear();
    m_accountCharacters.clear();
    m_nextCharacterId.store(1);
}

// Character updates (for future expansion)
bool CharacterDatabaseManager::updateCharacterLevel(uint32_t characterId, uint32_t newLevel)
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    auto it = m_characters.find(characterId);
    if (it != m_characters.end())
    {
        it->second.level = newLevel;
        return true;
    }

    return false;
}

bool CharacterDatabaseManager::updateCharacterPosition(uint32_t characterId, uint32_t x, uint32_t y, uint32_t z)
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    auto it = m_characters.find(characterId);
    if (it != m_characters.end())
    {
        it->second.x = x;
        it->second.y = y;
        it->second.z = z;
        return true;
    }

    return false;
}

// For testing and debugging
std::vector<uint32_t> CharacterDatabaseManager::getAllCharacterIds() const
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    std::vector<uint32_t> characterIds;
    characterIds.reserve(m_characters.size());

    for (const auto &[charId, character] : m_characters)
    {
        characterIds.push_back(charId);
    }

    std::sort(characterIds.begin(), characterIds.end());
    return characterIds;
}

std::vector<std::string> CharacterDatabaseManager::getAllAccountNames() const
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    std::vector<std::string> accountNames;
    accountNames.reserve(m_accountCharacters.size());

    for (const auto &[accountName, characterIds] : m_accountCharacters)
    {
        accountNames.push_back(accountName);
    }

    std::sort(accountNames.begin(), accountNames.end());
    return accountNames;
}

// Helper methods
uint32_t CharacterDatabaseManager::generateNextCharacterId()
{
    return m_nextCharacterId.fetch_add(1);
}

CharacterInfo CharacterDatabaseManager::createDefaultCharacter(const std::string &accountName, const std::string &characterName,
                                                               uint32_t race, uint32_t sex, uint32_t classId,
                                                               uint32_t hairStyle, uint32_t hairColor, uint32_t face)
{
    CharacterInfo character;

    // Basic info
    character.name = characterName;
    character.login_name = accountName;
    character.session_id = 0;    // Will be set during login
    character.clan_id = 0;       // No clan initially
    character.builder_level = 0; // Normal player
    character.sex = sex;
    character.race = race;
    character.class_id = classId;
    character.active = 1; // Character is active

    // Default starting position (safer coordinates for all races)
    character.x = -84318;
    character.y = 244579;
    character.z = -3730;

    // Default starting stats - Set proper starting HP/MP based on class/race
    character.level = 1;
    character.current_hp = 100.0;
    character.current_mp = 100.0;
    character.max_hp = 100.0; // Set max HP
    character.max_mp = 100.0; // Set max MP
    character.sp = 0;
    character.exp = 0;
    character.karma = 0;
    character.pk_kills = 0;
    character.pv_kills = 0;

    // Appearance data from character creation
    character.hair_style = hairStyle;
    character.hair_color = hairColor;
    character.face = face;

    // Initialize base stats that were missing
    // These should be set based on race/class but for now use defaults
    character.str_stat = 10;
    character.dex_stat = 10;
    character.con_stat = 10;
    character.int_stat = 10;
    character.wit_stat = 10;
    character.men_stat = 10;

    // Equipment slots - Initialize both object and item arrays
    character.paperdoll_object_ids.resize(16, 0); // Object IDs (all empty)
    character.paperdoll_item_ids.resize(16, 0);   // Item IDs (all empty)

    // Character state and deletion
    character.delete_timer = 0;        // Not scheduled for deletion
    character.base_class_id = classId; // Base class same as current class initially
    character.is_selected = 0;         // Not selected by default
    character.enchant_effect = 0;      // No enchant effect
    character.augmentation_id = 0;     // No weapon augmentation

    // Add logging to validate character creation
    std::cout << "[CharDB] Created character: " << characterName
              << " ID=" << character.char_id
              << " race=" << race << " sex=" << sex << " class=" << classId
              << " HP=" << character.current_hp << "/" << character.max_hp
              << " MP=" << character.current_mp << "/" << character.max_mp << std::endl;

    return character;
}

void CharacterDatabaseManager::addCharacterToAccount(const std::string &accountName, uint32_t characterId)
{
    auto &characterIds = m_accountCharacters[accountName];
    characterIds.push_back(characterId);
}

void CharacterDatabaseManager::removeCharacterFromAccount(const std::string &accountName, uint32_t characterId)
{
    auto accountIter = m_accountCharacters.find(accountName);
    if (accountIter != m_accountCharacters.end())
    {
        auto &characterIds = accountIter->second;
        characterIds.erase(std::remove(characterIds.begin(), characterIds.end(), characterId),
                           characterIds.end());

        // Remove account entry if no characters remain
        if (characterIds.empty())
        {
            m_accountCharacters.erase(accountIter);
        }
    }
}
