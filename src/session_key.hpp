#pragma once

#include <cstdint>
#include <random>

// Session Key Management for Lineage 2 authentication
// Matches Rust implementation in l2-core/src/session.rs
class SessionKey
{
public:
    int32_t play_ok1;
    int32_t play_ok2;
    int32_t login_ok1;
    int32_t login_ok2;

    // Default constructor
    SessionKey() = default;

    // Constructor with explicit values
    SessionKey(int32_t play1, int32_t play2, int32_t login1, int32_t login2)
        : play_ok1(play1), play_ok2(play2), login_ok1(login1), login_ok2(login2) {}

    // Generate random session key (matches Rust SessionKey::new())
    static SessionKey generate();

    // Check login server session (matches Rust check_session)
    bool check_session(int32_t s_key_1, int32_t s_key_2) const;

    // Compare sessions between servers (matches Rust equals)
    bool equals(const SessionKey &other, bool show_license) const;

    // Get play session ID (matches Rust get_play_session_id)
    int32_t get_play_session_id() const;

    // Equality operator
    bool operator==(const SessionKey &other) const;
    bool operator!=(const SessionKey &other) const;

    // Test function with Rust compatibility test vectors
    static void runTests();
};