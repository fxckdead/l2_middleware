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
    for (const auto &[charId, player] : m_characters)
    {
        if (player->getName() == characterName)
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

    // Generate character ID and create player
    uint32_t characterId = generateNextCharacterId();
    auto newPlayer = createDefaultPlayer(accountName, characterName, race, sex, classId,
                                         hairStyle, hairColor, face);
    newPlayer->setObjectId(characterId);

    // Store player and update account mapping
    m_characters[characterId] = std::move(newPlayer);
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
    if (charIter->second->getAccountName() != accountName)
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

    for (const auto &[charId, player] : m_characters)
    {
        if (player->getName() == characterName)
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
std::optional<Player *> CharacterDatabaseManager::getCharacterById(uint32_t characterId) const
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    auto it = m_characters.find(characterId);
    if (it != m_characters.end())
    {
        return it->second.get();
    }

    return std::nullopt;
}

std::optional<Player *> CharacterDatabaseManager::getCharacterBySlot(const std::string &accountName, uint32_t slotIndex) const
{
    auto characters = getCharactersForAccount(accountName);

    if (slotIndex < characters.size())
    {
        return characters[slotIndex];
    }

    return std::nullopt;
}

std::optional<Player *> CharacterDatabaseManager::getCharacterByName(const std::string &characterName) const
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    for (const auto &[charId, player] : m_characters)
    {
        if (player->getName() == characterName)
        {
            return player.get();
        }
    }

    return std::nullopt;
}

std::vector<Player *> CharacterDatabaseManager::getCharactersForAccount(const std::string &accountName) const
{
    std::lock_guard<std::mutex> lock(m_charactersMutex);

    std::vector<Player *> accountCharacters;

    auto accountIter = m_accountCharacters.find(accountName);
    if (accountIter != m_accountCharacters.end())
    {
        accountCharacters.reserve(accountIter->second.size());

        for (uint32_t characterId : accountIter->second)
        {
            auto charIter = m_characters.find(characterId);
            if (charIter != m_characters.end())
            {
                accountCharacters.push_back(charIter->second.get());
            }
        }
    }

    // Sort by character ID for consistent ordering
    std::sort(accountCharacters.begin(), accountCharacters.end(),
              [](const Player *a, const Player *b)
              {
                  return a->getObjectId() < b->getObjectId();
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
        it->second->setLevel(newLevel);
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
        it->second->setPosition(x, y, z);
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

    for (const auto &[charId, player] : m_characters)
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

std::unique_ptr<Player> CharacterDatabaseManager::createDefaultPlayer(const std::string &accountName, const std::string &characterName,
                                                                      uint32_t race, uint32_t sex, uint32_t classId,
                                                                      uint32_t hairStyle, uint32_t hairColor, uint32_t face)
{
    auto player = std::make_unique<Player>(0, characterName, accountName); // ObjectId will be set later

    // Basic info
    player->setSessionId(0); // Will be set during login
    player->setClanId(0);    // No clan initially
    player->setRace(race);
    player->setSex(sex);
    player->setClassId(classId);
    player->setBaseClassId(classId); // Base class same as current class initially

    // Default starting position (safer coordinates for all races)
    player->setPosition(-84318, 244579, -3730);

    // Default starting stats - Set proper starting HP/MP based on class/race
    player->setLevel(1);
    player->setCurrentHp(100.0);
    player->setMaxHp(100.0);
    player->setCurrentMp(100.0);
    player->setMaxMp(100.0);
    player->setSp(0);
    player->setExp(0);
    player->setKarma(0);
    player->setPkKills(0);
    player->setPvpKills(0);

    // Appearance data from character creation
    player->setHairStyle(hairStyle);
    player->setHairColor(hairColor);
    player->setFace(face);

    // Initialize base stats that were missing
    // These should be set based on race/class but for now use defaults
    player->setStr(10);
    player->setDex(10);
    player->setCon(10);
    player->setInt(10);
    player->setWit(10);
    player->setMen(10);

    // Equipment slots - Initialize both object and item arrays (already done in Player constructor)
    // The Player constructor already initializes 16 empty slots

    // Character state and deletion
    player->setDeleteTimer(0);    // Not scheduled for deletion
    player->setEnchantEffect(0);  // No enchant effect
    player->setAugmentationId(0); // No weapon augmentation

    // Add logging to validate character creation
    std::cout << "[CharDB] Created player: " << characterName
              << " race=" << race << " sex=" << sex << " class=" << classId
              << " HP=" << player->getCurrentHp() << "/" << player->getMaxHp()
              << " MP=" << player->getCurrentMp() << "/" << player->getMaxMp() << std::endl;

    return player;
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
