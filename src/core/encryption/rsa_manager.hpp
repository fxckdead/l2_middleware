#pragma once

#include <vector>
#include <random>
#include <memory>
#include <cstdint>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

// RSA key pair structure with actual private/public key data
struct RSAKeyPair
{
    std::vector<uint8_t> privateKey;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> modulus;

    RSAKeyPair(const std::vector<uint8_t> &privKey, const std::vector<uint8_t> &pubKey, const std::vector<uint8_t> &mod)
        : privateKey(privKey), publicKey(pubKey), modulus(mod) {}
};

class ScrambledRSAKeyPair
{
public:
    explicit ScrambledRSAKeyPair(const RSAKeyPair &keyPair);

    const std::vector<uint8_t> &getPrivateKey() const { return m_privateKey; }
    const std::vector<uint8_t> &getPublicKey() const { return m_publicKey; }
    const std::vector<uint8_t> &getOriginalModulus() const { return m_originalModulus; }
    const std::vector<uint8_t> &getScrambledModulus() const { return m_scrambledModulus; }

    // RSA operations
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &data) const;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &encryptedData) const;

private:
    std::vector<uint8_t> m_privateKey;
    std::vector<uint8_t> m_publicKey;
    std::vector<uint8_t> m_originalModulus;
    std::vector<uint8_t> m_scrambledModulus;

    // Helper function to scramble the modulus
    std::vector<uint8_t> scrambleModulus(const std::vector<uint8_t> &modulus);
};



class RSAManager
{
public:
    explicit RSAManager(uint8_t keyCount = 10);

    // Generate multiple RSA key pairs on startup
    void generateRSAKeyPairs(uint8_t count);

    // Get a random RSA key pair for client
    const ScrambledRSAKeyPair &getRandomRSAKeyPair();

    size_t getKeyPairCount() const { return m_keyPairs.size(); }



    // Static RSA utility functions
    static std::vector<uint8_t> rsaEncrypt(const std::vector<uint8_t> &data,
                                           const std::vector<uint8_t> &publicKey);
    static std::vector<uint8_t> rsaDecrypt(const std::vector<uint8_t> &encryptedData,
                                           const std::vector<uint8_t> &privateKey);
    static std::vector<uint8_t> rsaDecryptRaw(const std::vector<uint8_t> &encryptedData,
                                              const std::vector<uint8_t> &privateKey);



private:
    std::vector<std::unique_ptr<ScrambledRSAKeyPair>> m_keyPairs;
    std::random_device m_randomDevice;
    std::mt19937 m_rng;

    // Helper function to generate a single 1024-bit RSA key pair using OpenSSL
    RSAKeyPair generateRSAKeyPair();

    // Helper function to add sign byte to modulus
    std::vector<uint8_t> addSignByte(const std::vector<uint8_t> &modulus);


};