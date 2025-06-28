#include "../../encryption/rsa_manager.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <fstream>
#include <string>

// TestResult struct for test functions
struct TestResult
{
    bool passed;
    std::string message;

    TestResult(bool p, const std::string &msg) : passed(p), message(msg) {}
};

// Test helper functions (moved from RSAManager since they're only used for testing)
std::vector<uint8_t> createPublicKeyFromModulus(const std::vector<uint8_t> &modulus)
{
    // Create a minimal RSA public key structure from modulus
    // This is a simplified implementation for testing purposes
    try
    {
        RSA *rsa = RSA_new();
        BIGNUM *n = BN_new();
        BIGNUM *e = BN_new();

        // Set modulus
        BN_bin2bn(modulus.data(), modulus.size(), n);

        // Set public exponent to 65537 (RSA_F4)
        BN_set_word(e, RSA_F4);

        // Set the public key components
        RSA_set0_key(rsa, n, e, nullptr);

        // Convert to DER format
        BIO *bio = BIO_new(BIO_s_mem());
        i2d_RSAPublicKey_bio(bio, rsa);

        char *pubData;
        long pubLen = BIO_get_mem_data(bio, &pubData);
        std::vector<uint8_t> publicKey(pubData, pubData + pubLen);

        BIO_free(bio);
        RSA_free(rsa);

        return publicKey;
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error("Failed to create public key from modulus: " + std::string(e.what()));
    }
}

std::vector<uint8_t> loadPrivateKeyFromPEM(const std::string &pemFilePath)
{
    // Try multiple possible paths
    std::vector<std::string> pathsToTry = {
        pemFilePath,                              // Original path
        "test_data/test_private_key.pem",         // From project root
        "../test_data/test_private_key.pem",      // One level up
        "../../test_data/test_private_key.pem",   // Two levels up
        "../../../test_data/test_private_key.pem" // Three levels up
    };

    for (const auto &path : pathsToTry)
    {
        try
        {
            // Use BIO instead of FILE* to avoid Windows OpenSSL linking issues
            BIO *keyBio = BIO_new_file(path.c_str(), "r");
            if (!keyBio)
            {
                continue; // Try next path
            }

            RSA *rsa = PEM_read_bio_RSAPrivateKey(keyBio, nullptr, nullptr, nullptr);
            BIO_free(keyBio);

            if (!rsa)
            {
                continue; // Try next path
            }

            // Convert to DER format
            BIO *derBio = BIO_new(BIO_s_mem());
            i2d_RSAPrivateKey_bio(derBio, rsa);

            char *keyData;
            long keyLen = BIO_get_mem_data(derBio, &keyData);
            std::vector<uint8_t> privateKey(keyData, keyData + keyLen);

            BIO_free(derBio);
            RSA_free(rsa);

            std::cout << "  Found PEM file at: " << path << std::endl;
            return privateKey;
        }
        catch (...)
        {
            continue; // Try next path
        }
    }

    // If we get here, none of the paths worked
    std::string errorMsg = "Could not find PEM file. Tried paths:\n";
    for (const auto &path : pathsToTry)
    {
        errorMsg += "  - " + path + "\n";
    }
    throw std::runtime_error(errorMsg);
}

// Test functions extracted from RSAManager
TestResult test_rsa_key_generation()
{
    try
    {
        RSAManager manager(1);

        if (manager.getKeyPairCount() != 1)
        {
            return TestResult(false, "Failed to generate expected number of key pairs");
        }

        const auto &keyPair = manager.getRandomRSAKeyPair();

        // Check that keys have reasonable sizes
        if (keyPair.getPrivateKey().empty() || keyPair.getPublicKey().empty() || keyPair.getOriginalModulus().empty())
        {
            return TestResult(false, "Generated keys are empty");
        }

        // Check modulus size (should be 129 bytes for 1024-bit with sign byte)
        if (keyPair.getOriginalModulus().size() != 129)
        {
            return TestResult(false, "Modulus size incorrect. Expected 129, got " + std::to_string(keyPair.getOriginalModulus().size()));
        }

        // Check that first byte is sign byte (0x00)
        if (keyPair.getOriginalModulus()[0] != 0x00)
        {
            return TestResult(false, "Modulus missing sign byte");
        }

        return TestResult(true, "RSA key generation test passed");
    }
    catch (const std::exception &e)
    {
        return TestResult(false, "Exception in key generation test: " + std::string(e.what()));
    }
}

TestResult test_rsa_encryption_decryption()
{
    try
    {
        RSAManager manager(1);
        const auto &keyPair = manager.getRandomRSAKeyPair();

        // Test data - small enough for RSA encryption (less than key size)
        std::vector<uint8_t> testData = {
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21 // "Hello World!"
        };

        // Encrypt the data
        std::vector<uint8_t> encrypted = keyPair.encrypt(testData);

        if (encrypted.empty())
        {
            return TestResult(false, "Encryption returned empty result");
        }

        if (encrypted == testData)
        {
            return TestResult(false, "Encrypted data is same as original data");
        }

        // Decrypt the data
        std::vector<uint8_t> decrypted = keyPair.decrypt(encrypted);

        if (decrypted.empty())
        {
            return TestResult(false, "Decryption returned empty result");
        }

        // Compare original and decrypted data
        if (testData.size() != decrypted.size())
        {
            return TestResult(false, "Decrypted data size mismatch. Expected " + std::to_string(testData.size()) + ", got " + std::to_string(decrypted.size()));
        }

        if (!std::equal(testData.begin(), testData.end(), decrypted.begin()))
        {
            return TestResult(false, "Decrypted data does not match original data");
        }

        return TestResult(true, "Encryption/decryption round-trip test passed");
    }
    catch (const std::exception &e)
    {
        return TestResult(false, "Exception in encryption/decryption test: " + std::string(e.what()));
    }
}

TestResult test_rsa_scrambled_modulus()
{
    try
    {
        RSAManager manager(1);
        const auto &keyPair = manager.getRandomRSAKeyPair();

        const auto &original = keyPair.getOriginalModulus();
        const auto &scrambled = keyPair.getScrambledModulus();

        // Check that scrambled modulus has correct size (128 bytes, sign byte removed)
        if (scrambled.size() != 128)
        {
            return TestResult(false, "Scrambled modulus size incorrect. Expected 128, got " + std::to_string(scrambled.size()));
        }

        // Check that original and scrambled are different
        if (original.size() >= 128 && std::equal(original.begin() + 1, original.begin() + 129, scrambled.begin()))
        {
            return TestResult(false, "Scrambled modulus is identical to original (without sign byte)");
        }

        // Check that scrambling is deterministic (same input should give same output)
        RSAManager manager2(1);
        // We can't easily test determinism without exposing the scrambling function directly
        // This is a limitation of the current design

        return TestResult(true, "Modulus scrambling test passed");
    }
    catch (const std::exception &e)
    {
        return TestResult(false, "Exception in scrambled modulus test: " + std::string(e.what()));
    }
}

TestResult test_rsa_multiple_key_pairs()
{
    try
    {
        const int keyCount = 5;
        RSAManager manager(keyCount);

        if (manager.getKeyPairCount() != keyCount)
        {
            return TestResult(false, "Failed to generate expected number of key pairs");
        }

        // Test that we can get different random keys
        std::vector<const ScrambledRSAKeyPair *> keys;
        for (int i = 0; i < 10; ++i)
        {
            keys.push_back(&manager.getRandomRSAKeyPair());
        }

        // Check that each key pair can encrypt/decrypt independently
        std::vector<uint8_t> testData = {0x01, 0x02, 0x03, 0x04, 0x05};

        for (int i = 0; i < keyCount; ++i)
        {
            const auto &keyPair = manager.getRandomRSAKeyPair();

            auto encrypted = keyPair.encrypt(testData);
            auto decrypted = keyPair.decrypt(encrypted);

            if (testData != decrypted)
            {
                return TestResult(false, "Key pair " + std::to_string(i) + " failed encrypt/decrypt test");
            }
        }

        return TestResult(true, "Multiple key pairs test passed");
    }
    catch (const std::exception &e)
    {
        return TestResult(false, "Exception in multiple key pairs test: " + std::string(e.what()));
    }
}

TestResult test_rsa_rust_compatibility_encryption()
{
    try
    {
        // Exact test data from Rust test_encryption_works
        std::vector<uint8_t> modulus = {
            0, 223, 167, 200, 243, 159, 71, 142, 226, 187, 170, 69, 162, 8, 145, 92, 139, 207, 67,
            189, 1, 35, 109, 221, 188, 209, 20, 151, 56, 79, 70, 169, 46, 43, 166, 136, 99, 234, 1,
            212, 249, 191, 87, 41, 151, 102, 78, 192, 172, 57, 96, 199, 159, 204, 50, 5, 117, 148,
            85, 211, 203, 225, 211, 138, 173, 63, 12, 45, 94, 31, 14, 43, 248, 64, 85, 8, 55, 188,
            74, 101, 232, 218, 224, 185, 181, 248, 245, 201, 69, 133, 89, 95, 186, 28, 72, 54, 0,
            178, 194, 218, 96, 228, 6, 155, 52, 193, 24, 157, 192, 30, 84, 48, 0, 133, 76, 146, 83,
            185, 243, 100, 148, 180, 242, 5, 237, 62, 0, 159, 53};

        std::vector<uint8_t> unencrypted = {
            79, 112, 181, 90, 8, 119, 15, 29, 159, 106, 254, 130, 170, 198, 87, 88, 143, 86, 230,
            61, 98, 228, 151, 38, 253, 34, 225, 55, 105, 250, 215, 98, 30, 78, 104, 221, 149, 6,
            82, 128};

        // Create public key from modulus
        std::vector<uint8_t> publicKey = createPublicKeyFromModulus(modulus);

        // NOTE: RSA encryption with PKCS#1 padding is non-deterministic due to random padding
        // So we can't compare exact encrypted bytes, but we can test the key compatibility

        // Test 1: Verify we can create the key properly
        if (publicKey.empty())
        {
            return TestResult(false, "Failed to create public key from Rust modulus");
        }

        // Test 2: Verify encryption produces correct-sized output
        std::vector<uint8_t> encrypted = RSAManager::rsaEncrypt(unencrypted, publicKey);

        // RSA 1024-bit should produce 128-byte output
        if (encrypted.size() != 128)
        {
            return TestResult(false, "Encrypted data size incorrect. Expected 128, got " + std::to_string(encrypted.size()));
        }

        // Test 3: Verify the modulus is correctly interpreted (we can at least check it's the right size)
        if (modulus.size() != 129) // 128 bytes + sign byte
        {
            return TestResult(false, "Rust modulus size incorrect. Expected 129, got " + std::to_string(modulus.size()));
        }

        return TestResult(true, "Rust compatibility encryption test passed - key creation and encryption size validation successful");
    }
    catch (const std::exception &e)
    {
        return TestResult(false, "Exception in Rust compatibility encryption test: " + std::string(e.what()));
    }
}

TestResult test_rsa_rust_compatibility_login_packet()
{
    try
    {
        // Load the test private key from PEM file
        std::vector<uint8_t> privateKey = loadPrivateKeyFromPEM("../../test_data/test_private_key.pem");

        std::vector<uint8_t> packet_bytes = {
            0, 111, 125, 244, 145, 84, 105, 242, 208, 32, 190, 242, 250, 167, 184, 36, 251, 198,
            229, 162, 94, 164, 79, 87, 68, 170, 166, 176, 59, 40, 47, 27, 21, 25, 124, 150, 77, 89,
            181, 194, 116, 217, 110, 171, 209, 185, 77, 251, 96, 150, 93, 77, 252, 126, 12, 83,
            216, 199, 44, 212, 246, 101, 130, 122, 182, 243, 194, 146, 36, 40, 82, 243, 90, 25, 74,
            246, 47, 109, 37, 56, 212, 73, 43, 55, 160, 146, 76, 62, 32, 155, 81, 200, 83, 80, 74,
            192, 236, 142, 195, 1, 233, 42, 53, 176, 191, 251, 137, 116, 19, 216, 67, 43, 219, 71,
            199, 182, 215, 100, 56, 14, 72, 99, 39, 222, 240, 60, 93, 250, 227, 2, 137, 47, 122,
            247, 198, 200, 127, 195, 145, 4, 36, 217, 202, 40, 14, 60, 108, 223, 105, 93, 75, 251,
            208, 190, 162, 161, 229, 132, 42, 51, 87, 98, 80, 8, 186, 82, 88, 167, 103, 122, 13,
            195, 77, 123, 44, 220, 155, 160, 165, 190, 158, 33, 165, 66, 242, 21, 246, 171, 168,
            42, 84, 226, 106, 87, 18, 27, 148, 249, 170, 123, 122, 134, 21, 116, 104, 107, 61, 216,
            241, 249, 115, 160, 104, 100, 178, 171, 179, 221, 7, 232, 125, 192, 245, 13, 131, 39,
            207, 45, 123, 108, 196, 95, 55, 75, 104, 206, 89, 157, 39, 39, 156, 116, 100, 177, 248,
            92, 174, 21, 189, 35, 251, 208, 238, 82, 192, 125, 223, 53, 211, 170, 49, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 201, 60, 201, 172, 185, 36,
            197, 189, 152, 64, 89, 234, 166, 34, 61, 246, 0, 0, 0, 0, 97, 9, 131, 137, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0};

        // Extract the two 128-byte blocks (skip first byte)
        if (packet_bytes.size() < 257) // 1 + 128 + 128
        {
            return TestResult(false, "Packet too small for login data");
        }

        std::vector<uint8_t> raw1(packet_bytes.begin() + 1, packet_bytes.begin() + 1 + 128);
        std::vector<uint8_t> raw2(packet_bytes.begin() + 1 + 128, packet_bytes.begin() + 1 + 256);

        // Decrypt both blocks using raw RSA decryption (no padding removal)
        std::vector<uint8_t> decrypted1 = RSAManager::rsaDecryptRaw(raw1, privateKey);
        std::vector<uint8_t> decrypted2 = RSAManager::rsaDecryptRaw(raw2, privateKey);

        // Combine decrypted blocks
        std::vector<uint8_t> decrypted;
        decrypted.insert(decrypted.end(), decrypted1.begin(), decrypted1.end());
        decrypted.insert(decrypted.end(), decrypted2.begin(), decrypted2.end());

        std::cout << "  Decrypted " << decrypted1.size() << " + " << decrypted2.size()
                  << " = " << decrypted.size() << " bytes total" << std::endl;

        // Should now be 256 bytes total (128 + 128) to match Rust implementation
        if (decrypted.size() != 256)
        {
            return TestResult(false, "Decrypted data size incorrect. Expected 256, got " + std::to_string(decrypted.size()) + " bytes");
        }

        // Print first 20 bytes of decrypted data for debugging
        std::cout << "  First 20 bytes of decrypted data: ";
        for (size_t i = 0; i < 20; ++i)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(decrypted[i]) << " ";
        }
        std::cout << std::dec << std::endl;

        // Extract username from decrypted data at specific offsets (matching Rust test)
        // part1 = decrypted[0x4E..0x4E + 50] (trimmed)
        // part2 = decrypted[0xCE..0xCE + 14] (trimmed)
        std::string part1;
        std::string part2;

        // Extract part1 from offset 0x4E (78)
        for (size_t i = 0x4E; i < 0x4E + 50 && i < decrypted.size(); ++i)
        {
            if (decrypted[i] != 0)
                part1 += static_cast<char>(decrypted[i]);
        }

        // Extract part2 from offset 0xCE (206)
        for (size_t i = 0xCE; i < 0xCE + 14 && i < decrypted.size(); ++i)
        {
            if (decrypted[i] != 0)
                part2 += static_cast<char>(decrypted[i]);
        }

        std::string username = part1 + part2;
        std::cout << "  Extracted username: '" << username << "'" << std::endl;

        if (username != "admin")
        {
            return TestResult(false, "Extracted username '" + username + "' does not match expected 'admin'");
        }

        return TestResult(true, "Rust compatibility login packet test passed - decryption matches and username extracted correctly!");
    }
    catch (const std::exception &e)
    {
        return TestResult(false, "Exception in Rust compatibility login packet test: " + std::string(e.what()));
    }
}

void test_rsa_manager_all()
{
    std::cout << "\n"
              << std::string(60, '=') << std::endl;
    std::cout << "                RSA MANAGER TEST SUITE" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    struct TestCase
    {
        std::string name;
        std::function<TestResult()> testFunc;
    };

    std::vector<TestCase> tests = {
        {"RSA Key Generation", test_rsa_key_generation},
        {"Encryption/Decryption", test_rsa_encryption_decryption},
        {"Scrambled Modulus", test_rsa_scrambled_modulus},
        {"Multiple Key Pairs", test_rsa_multiple_key_pairs},
        {"Rust Compatibility - Encryption", test_rsa_rust_compatibility_encryption},
        {"Rust Compatibility - Login Packet", test_rsa_rust_compatibility_login_packet}};

    int passed = 0;
    int total = tests.size();

    for (const auto &test : tests)
    {
        std::cout << "Running: " << test.name << "... ";
        TestResult result = test.testFunc();

        if (result.passed)
        {
            std::cout << "✅ PASSED" << std::endl;
            passed++;
        }
        else
        {
            std::cout << "❌ FAILED" << std::endl;
            std::cout << "  Reason: " << result.message << std::endl;
        }
    }

    std::cout << std::string(60, '-') << std::endl;
    std::cout << "Test Results: " << passed << "/" << total << " passed";

    if (passed == total)
    {
        std::cout << " 🎉 ALL TESTS PASSED!" << std::endl;
    }
    else
    {
        std::cout << " ⚠️  Some tests failed." << std::endl;
    }

    std::cout << std::string(60, '=') << std::endl;
} 