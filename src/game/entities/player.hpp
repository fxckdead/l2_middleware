#pragma once

#include "creature.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

    // Forward declarations for stubbed classes
    class Clan;
    class Party;
    class Skill;
    class Item;
    


// Player class - represents a player character in the game
class Player : public Creature
{
private:
    // Core player properties (implemented for character selection)
    std::string accountName_;
    uint32_t sessionId_;
    uint32_t clanId_;
    uint32_t race_;           // 0=human, 1=elf, 2=dark_elf, 3=orc, 4=dwarf
    uint32_t classId_;
    uint32_t sex_;            // 0=male, 1=female
    uint32_t face_;
    uint32_t hairStyle_;
    uint32_t hairColor_;
    uint32_t karma_;
    uint32_t pvpKills_;
    uint32_t pkKills_;
    uint32_t fame_;
    uint32_t baseClassId_;
    uint32_t deleteTimer_;
    uint32_t enchantEffect_;
    uint32_t augmentationId_;
    
    // Equipment (paperdoll) - 16 slots each
    std::vector<uint32_t> paperdollObjectIds_;
    std::vector<uint32_t> paperdollItemIds_;

    // Stubbed properties (return defaults)
    std::vector<uint32_t> skills_;           // Stub: return empty vector
    Clan* clan_;                             // Stub: return nullptr
    Party* party_;                           // Stub: return nullptr
    std::vector<Item*> inventory_;           // Stub: return empty vector
    bool isOnline_;                          // Stub: return false
    bool isInDuel_;                          // Stub: return false
    bool isNoble_;                           // Stub: return false
    bool isHero_;                            // Stub: return false
    uint32_t accessLevel_;                   // Stub: return 0
    uint32_t mountNpcId_;                    // Stub: return 0
    uint32_t mountLevel_;                    // Stub: return 0
    uint32_t mountObjectId_;                 // Stub: return 0
    uint32_t agathionId_;                    // Stub: return 0
    uint32_t vitalityPoints_;                // Stub: return 0
    uint32_t pcCafePoints_;                  // Stub: return 0
    uint32_t onlineTime_;                    // Stub: return 0
    uint32_t lastAccess_;                    // Stub: return 0
    uint32_t createDate_;                    // Stub: return 0
    uint32_t lastRecomUpdate_;               // Stub: return 0
    uint32_t recomHave_;                     // Stub: return 0
    uint32_t recomLeft_;                     // Stub: return 0
    uint32_t deathPenaltyBuffLevel_;         // Stub: return 0
    uint32_t charges_;                       // Stub: return 0
    uint32_t powerGrade_;                    // Stub: return 0
    uint32_t pledgeClass_;                   // Stub: return 0
    uint32_t pledgeType_;                    // Stub: return 0
    uint32_t apprentice_;                    // Stub: return 0
    uint32_t sponsor_;                       // Stub: return 0
    uint32_t clanJoinExpiryTime_;            // Stub: return 0
    uint32_t clanCreateExpiryTime_;          // Stub: return 0
    uint32_t lvlJoinedAcademy_;              // Stub: return 0
    uint32_t wantsPeace_;                    // Stub: return 0
    uint32_t partyRoom_;                     // Stub: return 0
    uint32_t siegeState_;                    // Stub: return 0
    uint32_t siegeSide_;                     // Stub: return 0
    uint32_t olympiadGameId_;                // Stub: return 0
    uint32_t olympiadSide_;                  // Stub: return 0
    uint32_t olympiadBuffCount_;             // Stub: return 0
    uint32_t duelId_;                        // Stub: return 0
    uint32_t duelState_;                     // Stub: return 0
    uint32_t pvpFlag_;                       // Stub: return 0
    uint32_t pvpFlagLasts_;                  // Stub: return 0
    uint32_t teleMode_;                      // Stub: return 0
    uint32_t partyDistributionType_;         // Stub: return 0
    uint32_t privateStoreType_;              // Stub: return 0
    uint32_t dietMode_;                      // Stub: return 0
    uint32_t tradeRefusal_;                  // Stub: return 0
    uint32_t exchangeRefusal_;               // Stub: return 0
    uint32_t messageRefusal_;                // Stub: return 0
    uint32_t silenceMode_;                   // Stub: return 0
    uint32_t inventoryBlockingStatus_;       // Stub: return 0
    uint32_t expertiseArmorPenalty_;         // Stub: return 0
    uint32_t expertiseWeaponPenalty_;        // Stub: return 0
    uint32_t expertisePenaltyBonus_;         // Stub: return 0
    uint32_t weightPenalty_;                 // Stub: return 0
    uint32_t curWeightPenalty_;              // Stub: return 0
    uint32_t inventoryLimit_;                // Stub: return 0
    uint32_t warehouseLimit_;                // Stub: return 0
    uint32_t privateSellStoreLimit_;         // Stub: return 0
    uint32_t privateBuyStoreLimit_;          // Stub: return 0
    uint32_t dwarfRecipeLimit_;              // Stub: return 0
    uint32_t commonRecipeLimit_;             // Stub: return 0
    uint32_t questInventoryLimit_;           // Stub: return 0
    uint32_t bookmarkslot_;                  // Stub: return 0
    uint32_t language_;                      // Stub: return 0
    uint32_t faction_;                       // Stub: return 0
    uint32_t newbie_;                        // Stub: return 0
    uint32_t nobless_;                       // Stub: return 0
    uint32_t isIn7sDungeon_;                 // Stub: return 0
    uint32_t clanPrivileges_;                // Stub: return 0
    uint32_t subpledge_;                     // Stub: return 0
    uint32_t titleColor_;                    // Stub: return 0
    uint32_t title_;                         // Stub: return 0
    uint32_t cancraft_;                      // Stub: return 0
    uint32_t onlinetime_;                    // Stub: return 0
    uint32_t isin7sdungeon_;                 // Stub: return 0
    uint32_t last_recom_date_;               // Stub: return 0
    uint32_t rec_have_;                      // Stub: return 0
    uint32_t rec_left_;                      // Stub: return 0
    uint32_t death_penalty_level_;           // Stub: return 0
    uint32_t vitality_points_;               // Stub: return 0
    uint32_t pccafe_points_;                 // Stub: return 0

public:
    // Constructors
    Player(uint32_t objectId, const std::string& name, const std::string& accountName);
    virtual ~Player() = default;

    // Core methods (implemented for character selection)
    const std::string& getAccountName() const { return accountName_; }
    uint32_t getSessionId() const { return sessionId_; }
    uint32_t getClanId() const { return clanId_; }
    uint32_t getRace() const { return race_; }
    uint32_t getClassId() const { return classId_; }
    uint32_t getSex() const { return sex_; }
    uint32_t getFace() const { return face_; }
    uint32_t getHairStyle() const { return hairStyle_; }
    uint32_t getHairColor() const { return hairColor_; }
    uint32_t getKarma() const { return karma_; }
    uint32_t getPvpKills() const { return pvpKills_; }
    uint32_t getPkKills() const { return pkKills_; }
    uint32_t getFame() const { return fame_; }
    uint32_t getBaseClassId() const { return baseClassId_; }
    uint32_t getDeleteTimer() const { return deleteTimer_; }
    uint32_t getEnchantEffect() const { return enchantEffect_; }
    uint32_t getAugmentationId() const { return augmentationId_; }
    
    const std::vector<uint32_t>& getPaperdollObjectIds() const { return paperdollObjectIds_; }
    const std::vector<uint32_t>& getPaperdollItemIds() const { return paperdollItemIds_; }

    void setAccountName(const std::string& accountName) { accountName_ = accountName; }
    void setSessionId(uint32_t sessionId) { sessionId_ = sessionId; }
    void setClanId(uint32_t clanId) { clanId_ = clanId; }
    void setRace(uint32_t race) { race_ = race; }
    void setClassId(uint32_t classId) { classId_ = classId; }
    void setSex(uint32_t sex) { sex_ = sex; }
    void setFace(uint32_t face) { face_ = face; }
    void setHairStyle(uint32_t hairStyle) { hairStyle_ = hairStyle; }
    void setHairColor(uint32_t hairColor) { hairColor_ = hairColor; }
    void setKarma(uint32_t karma) { karma_ = karma; }
    void setPvpKills(uint32_t pvpKills) { pvpKills_ = pvpKills; }
    void setPkKills(uint32_t pkKills) { pkKills_ = pkKills; }
    void setFame(uint32_t fame) { fame_ = fame; }
    void setBaseClassId(uint32_t baseClassId) { baseClassId_ = baseClassId; }
    void setDeleteTimer(uint32_t deleteTimer) { deleteTimer_ = deleteTimer; }
    void setEnchantEffect(uint32_t enchantEffect) { enchantEffect_ = enchantEffect; }
    void setAugmentationId(uint32_t augmentationId) { augmentationId_ = augmentationId; }
    
    void setPaperdollObjectId(size_t slot, uint32_t objectId);
    void setPaperdollItemId(size_t slot, uint32_t itemId);

    // Debug method
    void dump() const;

    // Stubbed methods (return defaults)
    [[maybe_unused]] const std::vector<uint32_t>& getSkills() const { return skills_; }
    [[maybe_unused]] Clan* getClan() const { return clan_; }
    [[maybe_unused]] Party* getParty() const { return party_; }
    [[maybe_unused]] const std::vector<Item*>& getInventory() const { return inventory_; }
    [[maybe_unused]] bool isOnline() const { return isOnline_; }
    [[maybe_unused]] bool isInDuel() const { return isInDuel_; }
    [[maybe_unused]] bool isNoble() const { return isNoble_; }
    [[maybe_unused]] bool isHero() const { return isHero_; }
    [[maybe_unused]] uint32_t getAccessLevel() const { return accessLevel_; }
    [[maybe_unused]] uint32_t getMountNpcId() const { return mountNpcId_; }
    [[maybe_unused]] uint32_t getMountLevel() const { return mountLevel_; }
    [[maybe_unused]] uint32_t getMountObjectId() const { return mountObjectId_; }
    [[maybe_unused]] uint32_t getAgathionId() const { return agathionId_; }
    [[maybe_unused]] uint32_t getVitalityPoints() const { return vitalityPoints_; }
    [[maybe_unused]] uint32_t getPcCafePoints() const { return pcCafePoints_; }
    [[maybe_unused]] uint32_t getOnlineTime() const { return onlineTime_; }
    [[maybe_unused]] uint32_t getLastAccess() const { return lastAccess_; }
    [[maybe_unused]] uint32_t getCreateDate() const { return createDate_; }
    [[maybe_unused]] uint32_t getLastRecomUpdate() const { return lastRecomUpdate_; }
    [[maybe_unused]] uint32_t getRecomHave() const { return recomHave_; }
    [[maybe_unused]] uint32_t getRecomLeft() const { return recomLeft_; }
    [[maybe_unused]] uint32_t getDeathPenaltyBuffLevel() const { return deathPenaltyBuffLevel_; }
    [[maybe_unused]] uint32_t getCharges() const { return charges_; }
    [[maybe_unused]] uint32_t getPowerGrade() const { return powerGrade_; }
    [[maybe_unused]] uint32_t getPledgeClass() const { return pledgeClass_; }
    [[maybe_unused]] uint32_t getPledgeType() const { return pledgeType_; }
    [[maybe_unused]] uint32_t getApprentice() const { return apprentice_; }
    [[maybe_unused]] uint32_t getSponsor() const { return sponsor_; }
    [[maybe_unused]] uint32_t getClanJoinExpiryTime() const { return clanJoinExpiryTime_; }
    [[maybe_unused]] uint32_t getClanCreateExpiryTime() const { return clanCreateExpiryTime_; }
    [[maybe_unused]] uint32_t getLvlJoinedAcademy() const { return lvlJoinedAcademy_; }
    [[maybe_unused]] uint32_t getWantsPeace() const { return wantsPeace_; }
    [[maybe_unused]] uint32_t getPartyRoom() const { return partyRoom_; }
    [[maybe_unused]] uint32_t getSiegeState() const { return siegeState_; }
    [[maybe_unused]] uint32_t getSiegeSide() const { return siegeSide_; }
    [[maybe_unused]] uint32_t getOlympiadGameId() const { return olympiadGameId_; }
    [[maybe_unused]] uint32_t getOlympiadSide() const { return olympiadSide_; }
    [[maybe_unused]] uint32_t getOlympiadBuffCount() const { return olympiadBuffCount_; }
    [[maybe_unused]] uint32_t getDuelId() const { return duelId_; }
    [[maybe_unused]] uint32_t getDuelState() const { return duelState_; }
    [[maybe_unused]] uint32_t getPvpFlag() const { return pvpFlag_; }
    [[maybe_unused]] uint32_t getPvpFlagLasts() const { return pvpFlagLasts_; }
    [[maybe_unused]] uint32_t getTeleMode() const { return teleMode_; }
    [[maybe_unused]] uint32_t getPartyDistributionType() const { return partyDistributionType_; }
    [[maybe_unused]] uint32_t getPrivateStoreType() const { return privateStoreType_; }
    [[maybe_unused]] uint32_t getDietMode() const { return dietMode_; }
    [[maybe_unused]] uint32_t getTradeRefusal() const { return tradeRefusal_; }
    [[maybe_unused]] uint32_t getExchangeRefusal() const { return exchangeRefusal_; }
    [[maybe_unused]] uint32_t getMessageRefusal() const { return messageRefusal_; }
    [[maybe_unused]] uint32_t getSilenceMode() const { return silenceMode_; }
    [[maybe_unused]] uint32_t getInventoryBlockingStatus() const { return inventoryBlockingStatus_; }
    [[maybe_unused]] uint32_t getExpertiseArmorPenalty() const { return expertiseArmorPenalty_; }
    [[maybe_unused]] uint32_t getExpertiseWeaponPenalty() const { return expertiseWeaponPenalty_; }
    [[maybe_unused]] uint32_t getExpertisePenaltyBonus() const { return expertisePenaltyBonus_; }
    [[maybe_unused]] uint32_t getWeightPenalty() const { return weightPenalty_; }
    [[maybe_unused]] uint32_t getCurWeightPenalty() const { return curWeightPenalty_; }
    [[maybe_unused]] uint32_t getInventoryLimit() const { return inventoryLimit_; }
    [[maybe_unused]] uint32_t getWarehouseLimit() const { return warehouseLimit_; }
    [[maybe_unused]] uint32_t getPrivateSellStoreLimit() const { return privateSellStoreLimit_; }
    [[maybe_unused]] uint32_t getPrivateBuyStoreLimit() const { return privateBuyStoreLimit_; }
    [[maybe_unused]] uint32_t getDwarfRecipeLimit() const { return dwarfRecipeLimit_; }
    [[maybe_unused]] uint32_t getCommonRecipeLimit() const { return commonRecipeLimit_; }
    [[maybe_unused]] uint32_t getQuestInventoryLimit() const { return questInventoryLimit_; }
    [[maybe_unused]] uint32_t getBookmarkslot() const { return bookmarkslot_; }
    [[maybe_unused]] uint32_t getLanguage() const { return language_; }
    [[maybe_unused]] uint32_t getFaction() const { return faction_; }
    [[maybe_unused]] uint32_t getNewbie() const { return newbie_; }
    [[maybe_unused]] uint32_t getNobless() const { return nobless_; }
    [[maybe_unused]] uint32_t getIsIn7sDungeon() const { return isIn7sDungeon_; }
    [[maybe_unused]] uint32_t getClanPrivileges() const { return clanPrivileges_; }
    [[maybe_unused]] uint32_t getSubpledge() const { return subpledge_; }
    [[maybe_unused]] uint32_t getTitleColor() const { return titleColor_; }
    [[maybe_unused]] uint32_t getTitle() const { return title_; }
    [[maybe_unused]] uint32_t getCancraft() const { return cancraft_; }
    [[maybe_unused]] uint32_t getOnlinetime() const { return onlinetime_; }
    [[maybe_unused]] uint32_t getIsin7sdungeon() const { return isin7sdungeon_; }
    [[maybe_unused]] uint32_t getLastRecomDate() const { return last_recom_date_; }
    [[maybe_unused]] uint32_t getRecHave() const { return rec_have_; }
    [[maybe_unused]] uint32_t getRecLeft() const { return rec_left_; }
    [[maybe_unused]] uint32_t getDeathPenaltyLevel() const { return death_penalty_level_; }
    [[maybe_unused]] uint32_t getPccafePoints() const { return pccafe_points_; }

    // Stubbed setters
    [[maybe_unused]] void setSkills(const std::vector<uint32_t>& skills) { skills_ = skills; }
    [[maybe_unused]] void setClan(Clan* clan) { clan_ = clan; }
    [[maybe_unused]] void setParty(Party* party) { party_ = party; }
    [[maybe_unused]] void setInventory(const std::vector<Item*>& inventory) { inventory_ = inventory; }
    [[maybe_unused]] void setOnline(bool online) { isOnline_ = online; }
    [[maybe_unused]] void setInDuel(bool inDuel) { isInDuel_ = inDuel; }
    [[maybe_unused]] void setNoble(bool noble) { isNoble_ = noble; }
    [[maybe_unused]] void setHero(bool hero) { isHero_ = hero; }
    [[maybe_unused]] void setAccessLevel(uint32_t accessLevel) { accessLevel_ = accessLevel; }
    [[maybe_unused]] void setMountNpcId(uint32_t mountNpcId) { mountNpcId_ = mountNpcId; }
    [[maybe_unused]] void setMountLevel(uint32_t mountLevel) { mountLevel_ = mountLevel; }
    [[maybe_unused]] void setMountObjectId(uint32_t mountObjectId) { mountObjectId_ = mountObjectId; }
    [[maybe_unused]] void setAgathionId(uint32_t agathionId) { agathionId_ = agathionId; }
    [[maybe_unused]] void setVitalityPoints(uint32_t vitalityPoints) { vitalityPoints_ = vitalityPoints; }
    [[maybe_unused]] void setPcCafePoints(uint32_t pcCafePoints) { pcCafePoints_ = pcCafePoints; }
    [[maybe_unused]] void setOnlineTime(uint32_t onlineTime) { onlineTime_ = onlineTime; }
    [[maybe_unused]] void setLastAccess(uint32_t lastAccess) { lastAccess_ = lastAccess; }
    [[maybe_unused]] void setCreateDate(uint32_t createDate) { createDate_ = createDate; }
    [[maybe_unused]] void setLastRecomUpdate(uint32_t lastRecomUpdate) { lastRecomUpdate_ = lastRecomUpdate; }
    [[maybe_unused]] void setRecomHave(uint32_t recomHave) { recomHave_ = recomHave; }
    [[maybe_unused]] void setRecomLeft(uint32_t recomLeft) { recomLeft_ = recomLeft; }
    [[maybe_unused]] void setDeathPenaltyBuffLevel(uint32_t deathPenaltyBuffLevel) { deathPenaltyBuffLevel_ = deathPenaltyBuffLevel; }
    [[maybe_unused]] void setCharges(uint32_t charges) { charges_ = charges; }
    [[maybe_unused]] void setPowerGrade(uint32_t powerGrade) { powerGrade_ = powerGrade; }
    [[maybe_unused]] void setPledgeClass(uint32_t pledgeClass) { pledgeClass_ = pledgeClass; }
    [[maybe_unused]] void setPledgeType(uint32_t pledgeType) { pledgeType_ = pledgeType; }
    [[maybe_unused]] void setApprentice(uint32_t apprentice) { apprentice_ = apprentice; }
    [[maybe_unused]] void setSponsor(uint32_t sponsor) { sponsor_ = sponsor; }
    [[maybe_unused]] void setClanJoinExpiryTime(uint32_t clanJoinExpiryTime) { clanJoinExpiryTime_ = clanJoinExpiryTime; }
    [[maybe_unused]] void setClanCreateExpiryTime(uint32_t clanCreateExpiryTime) { clanCreateExpiryTime_ = clanCreateExpiryTime; }
    [[maybe_unused]] void setLvlJoinedAcademy(uint32_t lvlJoinedAcademy) { lvlJoinedAcademy_ = lvlJoinedAcademy; }
    [[maybe_unused]] void setWantsPeace(uint32_t wantsPeace) { wantsPeace_ = wantsPeace; }
    [[maybe_unused]] void setPartyRoom(uint32_t partyRoom) { partyRoom_ = partyRoom; }
    [[maybe_unused]] void setSiegeState(uint32_t siegeState) { siegeState_ = siegeState; }
    [[maybe_unused]] void setSiegeSide(uint32_t siegeSide) { siegeSide_ = siegeSide; }
    [[maybe_unused]] void setOlympiadGameId(uint32_t olympiadGameId) { olympiadGameId_ = olympiadGameId; }
    [[maybe_unused]] void setOlympiadSide(uint32_t olympiadSide) { olympiadSide_ = olympiadSide; }
    [[maybe_unused]] void setOlympiadBuffCount(uint32_t olympiadBuffCount) { olympiadBuffCount_ = olympiadBuffCount; }
    [[maybe_unused]] void setDuelId(uint32_t duelId) { duelId_ = duelId; }
    [[maybe_unused]] void setDuelState(uint32_t duelState) { duelState_ = duelState; }
    [[maybe_unused]] void setPvpFlag(uint32_t pvpFlag) { pvpFlag_ = pvpFlag; }
    [[maybe_unused]] void setPvpFlagLasts(uint32_t pvpFlagLasts) { pvpFlagLasts_ = pvpFlagLasts; }
    [[maybe_unused]] void setTeleMode(uint32_t teleMode) { teleMode_ = teleMode; }
    [[maybe_unused]] void setPartyDistributionType(uint32_t partyDistributionType) { partyDistributionType_ = partyDistributionType; }
    [[maybe_unused]] void setPrivateStoreType(uint32_t privateStoreType) { privateStoreType_ = privateStoreType; }
    [[maybe_unused]] void setDietMode(uint32_t dietMode) { dietMode_ = dietMode; }
    [[maybe_unused]] void setTradeRefusal(uint32_t tradeRefusal) { tradeRefusal_ = tradeRefusal; }
    [[maybe_unused]] void setExchangeRefusal(uint32_t exchangeRefusal) { exchangeRefusal_ = exchangeRefusal; }
    [[maybe_unused]] void setMessageRefusal(uint32_t messageRefusal) { messageRefusal_ = messageRefusal; }
    [[maybe_unused]] void setSilenceMode(uint32_t silenceMode) { silenceMode_ = silenceMode; }
    [[maybe_unused]] void setInventoryBlockingStatus(uint32_t inventoryBlockingStatus) { inventoryBlockingStatus_ = inventoryBlockingStatus; }
    [[maybe_unused]] void setExpertiseArmorPenalty(uint32_t expertiseArmorPenalty) { expertiseArmorPenalty_ = expertiseArmorPenalty; }
    [[maybe_unused]] void setExpertiseWeaponPenalty(uint32_t expertiseWeaponPenalty) { expertiseWeaponPenalty_ = expertiseWeaponPenalty; }
    [[maybe_unused]] void setExpertisePenaltyBonus(uint32_t expertisePenaltyBonus) { expertisePenaltyBonus_ = expertisePenaltyBonus; }
    [[maybe_unused]] void setWeightPenalty(uint32_t weightPenalty) { weightPenalty_ = weightPenalty; }
    [[maybe_unused]] void setCurWeightPenalty(uint32_t curWeightPenalty) { curWeightPenalty_ = curWeightPenalty; }
    [[maybe_unused]] void setInventoryLimit(uint32_t inventoryLimit) { inventoryLimit_ = inventoryLimit; }
    [[maybe_unused]] void setWarehouseLimit(uint32_t warehouseLimit) { warehouseLimit_ = warehouseLimit; }
    [[maybe_unused]] void setPrivateSellStoreLimit(uint32_t privateSellStoreLimit) { privateSellStoreLimit_ = privateSellStoreLimit; }
    [[maybe_unused]] void setPrivateBuyStoreLimit(uint32_t privateBuyStoreLimit) { privateBuyStoreLimit_ = privateBuyStoreLimit; }
    [[maybe_unused]] void setDwarfRecipeLimit(uint32_t dwarfRecipeLimit) { dwarfRecipeLimit_ = dwarfRecipeLimit; }
    [[maybe_unused]] void setCommonRecipeLimit(uint32_t commonRecipeLimit) { commonRecipeLimit_ = commonRecipeLimit; }
    [[maybe_unused]] void setQuestInventoryLimit(uint32_t questInventoryLimit) { questInventoryLimit_ = questInventoryLimit; }
    [[maybe_unused]] void setBookmarkslot(uint32_t bookmarkslot) { bookmarkslot_ = bookmarkslot; }
    [[maybe_unused]] void setLanguage(uint32_t language) { language_ = language; }
    [[maybe_unused]] void setFaction(uint32_t faction) { faction_ = faction; }
    [[maybe_unused]] void setNewbie(uint32_t newbie) { newbie_ = newbie; }
    [[maybe_unused]] void setNobless(uint32_t nobless) { nobless_ = nobless; }
    [[maybe_unused]] void setIsIn7sDungeon(uint32_t isIn7sDungeon) { isIn7sDungeon_ = isIn7sDungeon; }
    [[maybe_unused]] void setClanPrivileges(uint32_t clanPrivileges) { clanPrivileges_ = clanPrivileges; }
    [[maybe_unused]] void setSubpledge(uint32_t subpledge) { subpledge_ = subpledge; }
    [[maybe_unused]] void setTitleColor(uint32_t titleColor) { titleColor_ = titleColor; }
    [[maybe_unused]] void setTitle(uint32_t title) { title_ = title; }
    [[maybe_unused]] void setCancraft(uint32_t cancraft) { cancraft_ = cancraft; }
    [[maybe_unused]] void setOnlinetime(uint32_t onlinetime) { onlinetime_ = onlinetime; }
    [[maybe_unused]] void setIsin7sdungeon(uint32_t isin7sdungeon) { isin7sdungeon_ = isin7sdungeon; }
    [[maybe_unused]] void setLastRecomDate(uint32_t lastRecomDate) { last_recom_date_ = lastRecomDate; }
    [[maybe_unused]] void setRecHave(uint32_t recHave) { rec_have_ = recHave; }
    [[maybe_unused]] void setRecLeft(uint32_t recLeft) { rec_left_ = recLeft; }
    [[maybe_unused]] void setDeathPenaltyLevel(uint32_t deathPenaltyLevel) { death_penalty_level_ = deathPenaltyLevel; }
    [[maybe_unused]] void setPccafePoints(uint32_t pccafePoints) { pccafe_points_ = pccafePoints; }
}; 