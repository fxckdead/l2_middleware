#include "rsa_manager.hpp"
#include <stdexcept>
#include <algorithm>

// Note: Removed applink.c due to compilation issues on this setup

ScrambledRSAKeyPair::ScrambledRSAKeyPair(const RSAKeyPair &keyPair)
    : m_privateKey(keyPair.privateKey),
      m_publicKey(keyPair.publicKey),
      m_originalModulus(keyPair.modulus)
{
    // Create scrambled version of the modulus for client transmission
    m_scrambledModulus = scrambleModulus(m_originalModulus);
}

std::vector<uint8_t> ScrambledRSAKeyPair::scrambleModulus(const std::vector<uint8_t> &modulus)
{
    std::vector<uint8_t> data = modulus;

    // Remove leading zero if 129 bytes
    if (data.size() == 129 && data[0] == 0x00)
    {
        data.erase(data.begin()); // Remove first byte, now 128 bytes
    }

    // Ensure we have exactly 128 bytes for scrambling
    if (data.size() != 128)
    {
        throw std::runtime_error("Invalid modulus size for scrambling");
    }

    // Step 1: Swap bytes 0x00-0x04 with 0x4D-0x50
    for (int i = 0; i < 4; ++i)
    {
        std::swap(data[i], data[0x4D + i]);
    }

    // Step 2: XOR first 64 bytes with last 64 bytes
    for (int i = 0; i < 64; ++i)
    {
        data[i] ^= data[64 + i];
    }

    // Step 3: XOR bytes 0x0D-0x10 with 0x34-0x38
    for (int i = 0; i < 4; ++i)
    {
        data[0x0D + i] ^= data[0x34 + i];
    }

    // Step 4: XOR last 64 bytes with first 64 bytes
    for (int i = 0; i < 64; ++i)
    {
        data[64 + i] ^= data[i];
    }

    return data;
}

RSAManager::RSAManager(uint8_t keyCount)
    : m_rng(m_randomDevice())
{
    generateRSAKeyPairs(keyCount);
}

void RSAManager::generateRSAKeyPairs(uint8_t count)
{
    m_keyPairs.clear();
    m_keyPairs.reserve(count);

    for (uint8_t i = 0; i < count; ++i)
    {
        RSAKeyPair rsaPair = generateRSAKeyPair();
        auto scrambledPair = std::make_unique<ScrambledRSAKeyPair>(rsaPair);
        m_keyPairs.push_back(std::move(scrambledPair));
    }
}

const ScrambledRSAKeyPair &RSAManager::getRandomRSAKeyPair()
{
    if (m_keyPairs.empty())
    {
        throw std::runtime_error("No RSA key pairs available");
    }

    std::uniform_int_distribution<size_t> dist(0, m_keyPairs.size() - 1);
    size_t randomIndex = dist(m_rng);

    return *m_keyPairs[randomIndex];
}

std::vector<uint8_t> RSAManager::addSignByte(const std::vector<uint8_t> &modulus)
{
    std::vector<uint8_t> result;
    result.reserve(modulus.size() + 1);

    // Add 0x00 byte for positive number (as per RSA standard)
    result.push_back(0x00);
    result.insert(result.end(), modulus.begin(), modulus.end());

    return result;
}

RSAKeyPair RSAManager::generateRSAKeyPair()
{
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4); // 65537

    if (RSA_generate_key_ex(rsa, 1024, e, nullptr) != 1)
    {
        BN_free(e);
        RSA_free(rsa);
        throw std::runtime_error("Failed to generate RSA key pair");
    }

    // Extract modulus
    const BIGNUM *n = RSA_get0_n(rsa);
    int modulusLen = BN_num_bytes(n);
    std::vector<uint8_t> modulus(modulusLen);
    BN_bn2bin(n, modulus.data());

    // Convert private key to DER format
    BIO *privBio = BIO_new(BIO_s_mem());
    i2d_RSAPrivateKey_bio(privBio, rsa);

    char *privData;
    long privLen = BIO_get_mem_data(privBio, &privData);
    std::vector<uint8_t> privateKey(privData, privData + privLen);

    // Convert public key to DER format
    BIO *pubBio = BIO_new(BIO_s_mem());
    i2d_RSAPublicKey_bio(pubBio, rsa);

    char *pubData;
    long pubLen = BIO_get_mem_data(pubBio, &pubData);
    std::vector<uint8_t> publicKey(pubData, pubData + pubLen);

    // Clean up
    BIO_free(privBio);
    BIO_free(pubBio);
    BN_free(e);
    RSA_free(rsa);

    // Add sign byte to modulus for transmission
    std::vector<uint8_t> modulusWithSign = addSignByte(modulus);

    return RSAKeyPair(privateKey, publicKey, modulusWithSign);
}

std::vector<uint8_t> RSAManager::rsaEncrypt(const std::vector<uint8_t> &data,
                                            const std::vector<uint8_t> &publicKey)
{
    // Create RSA structure from DER-encoded public key
    const unsigned char *pubKeyPtr = publicKey.data();
    RSA *rsa = d2i_RSAPublicKey(nullptr, &pubKeyPtr, publicKey.size());

    if (!rsa)
    {
        throw std::runtime_error("Failed to parse RSA public key");
    }

    // Use PKCS#1 padding for normal encryption (safer and works with arbitrary data sizes)
    std::vector<uint8_t> encrypted(RSA_size(rsa));
    int encryptedLen = RSA_public_encrypt(data.size(), data.data(),
                                          encrypted.data(), rsa, RSA_PKCS1_PADDING);

    RSA_free(rsa);

    if (encryptedLen < 0)
    {
        throw std::runtime_error("RSA encryption failed");
    }

    encrypted.resize(encryptedLen);
    return encrypted;
}

std::vector<uint8_t> RSAManager::rsaDecrypt(const std::vector<uint8_t> &encryptedData,
                                            const std::vector<uint8_t> &privateKey)
{
    // Create RSA structure from DER-encoded private key
    const unsigned char *privKeyPtr = privateKey.data();
    RSA *rsa = d2i_RSAPrivateKey(nullptr, &privKeyPtr, privateKey.size());

    if (!rsa)
    {
        throw std::runtime_error("Failed to parse RSA private key");
    }

    // Use PKCS#1 padding for normal decryption
    std::vector<uint8_t> decrypted(RSA_size(rsa));
    int decryptedLen = RSA_private_decrypt(encryptedData.size(), encryptedData.data(),
                                           decrypted.data(), rsa, RSA_PKCS1_PADDING);

    RSA_free(rsa);

    if (decryptedLen < 0)
    {
        throw std::runtime_error("RSA decryption failed");
    }

    decrypted.resize(decryptedLen);
    return decrypted;
}

std::vector<uint8_t> RSAManager::rsaDecryptRaw(const std::vector<uint8_t> &encryptedData,
                                               const std::vector<uint8_t> &privateKey)
{
    // Create RSA structure from DER-encoded private key
    const unsigned char *privKeyPtr = privateKey.data();
    RSA *rsa = d2i_RSAPrivateKey(nullptr, &privKeyPtr, privateKey.size());

    if (!rsa)
    {
        throw std::runtime_error("Failed to parse RSA private key");
    }

    // Get RSA parameters (same as Rust approach)
    const BIGNUM *n = RSA_get0_n(rsa);
    const BIGNUM *d = RSA_get0_d(rsa);
    int keySize = RSA_size(rsa);

    // Convert encrypted data to BIGNUM (same as Rust: BigUint::from_bytes_be)
    BIGNUM *c = BN_bin2bn(encryptedData.data(), encryptedData.size(), nullptr);
    if (!c)
    {
        RSA_free(rsa);
        throw std::runtime_error("Failed to convert encrypted data to BIGNUM");
    }

    // Perform modular exponentiation: c^d mod n (same as Rust: c.modpow(d, n))
    BIGNUM *m = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    if (BN_mod_exp(m, c, d, n, ctx) != 1)
    {
        BN_free(c);
        BN_free(m);
        BN_CTX_free(ctx);
        RSA_free(rsa);
        throw std::runtime_error("RSA modular exponentiation failed");
    }

    // Convert result back to bytes (same as Rust: to_bytes_be())
    int resultLen = BN_num_bytes(m);
    std::vector<uint8_t> decrypted(keySize, 0); // Initialize with zeros

    // Get the actual decrypted bytes
    std::vector<uint8_t> tempResult(resultLen);
    BN_bn2bin(m, tempResult.data());

    // Pad with leading zeros to key size (same as Rust padding logic)
    if (resultLen < keySize)
    {
        int padLength = keySize - resultLen;
        std::copy(tempResult.begin(), tempResult.end(), decrypted.begin() + padLength);
    }
    else
    {
        std::copy(tempResult.begin(), tempResult.end(), decrypted.begin());
    }

    // Cleanup
    BN_free(c);
    BN_free(m);
    BN_CTX_free(ctx);
    RSA_free(rsa);

    return decrypted;
}

std::vector<uint8_t> ScrambledRSAKeyPair::encrypt(const std::vector<uint8_t> &data) const
{
    return RSAManager::rsaEncrypt(data, m_publicKey);
}

std::vector<uint8_t> ScrambledRSAKeyPair::decrypt(const std::vector<uint8_t> &encryptedData) const
{
    return RSAManager::rsaDecrypt(encryptedData, m_privateKey);
}
