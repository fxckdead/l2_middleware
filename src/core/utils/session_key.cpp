#include "session_key.hpp"

// Generate random session key (matches Rust SessionKey::new())
SessionKey SessionKey::generate()
{
    static std::random_device rd;
    static std::mt19937 gen(rd());

    return SessionKey{
        static_cast<int32_t>(gen()),
        static_cast<int32_t>(gen()),
        static_cast<int32_t>(gen()),
        static_cast<int32_t>(gen())};
}

// Check login server session (matches Rust check_session)
bool SessionKey::check_session(int32_t s_key_1, int32_t s_key_2) const
{
    return s_key_1 == login_ok1 && s_key_2 == login_ok2;
}

// Compare sessions between servers (matches Rust equals)
bool SessionKey::equals(const SessionKey &other, bool show_license) const
{
    bool is_play_ok = play_ok1 == other.play_ok1 && play_ok2 == other.play_ok2;

    if (show_license)
    {
        return is_play_ok && login_ok1 == other.login_ok1 && login_ok2 == other.login_ok2;
    }

    return is_play_ok;
}

// Get play session ID (matches Rust get_play_session_id)
int32_t SessionKey::get_play_session_id() const
{
    return play_ok1;
}

// Equality operator
bool SessionKey::operator==(const SessionKey &other) const
{
    return play_ok1 == other.play_ok1 &&
           play_ok2 == other.play_ok2 &&
           login_ok1 == other.login_ok1 &&
           login_ok2 == other.login_ok2;
}

bool SessionKey::operator!=(const SessionKey &other) const
{
    return !(*this == other);
}
