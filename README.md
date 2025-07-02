# L2 Middlewares

A modern C++20 TCP server implementation for Lineage 2 game emulation, featuring separate Login and Game server components.

## 🚀 Features

- **Login Server**: Handles client authentication, server list, and session management
- **Game Server**: Manages character selection, world entry, and game logic
- **Modern C++20**: Built with modern C++ standards and best practices
- **Cross-platform**: Windows and Linux support
- **Encrypted Communication**: RSA, Blowfish, and XOR encryption support
- **Modular Architecture**: Clean separation between Core, Login, and Game components

## 📋 Prerequisites

### Required Software

- **CMake 3.21+** - Build system
- **C++20 compatible compiler**:
  - Windows: Visual Studio 2019+ or MinGW-w64
  - Linux: GCC 10+ or Clang 12+
- **vcpkg** - C++ package manager
- **Ninja** - Build generator (recommended)

### Install vcpkg

If you don't have vcpkg installed:

#### Windows
```powershell
# Clone vcpkg
git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg

# Bootstrap vcpkg
.\bootstrap-vcpkg.bat

# Set environment variable (add to your system PATH)
setx VCPKG_ROOT "C:\vcpkg"
```

#### Linux/macOS
```bash
# Clone vcpkg
git clone https://github.com/Microsoft/vcpkg.git ~/vcpkg
cd ~/vcpkg

# Bootstrap vcpkg
./bootstrap-vcpkg.sh

# Add to your shell profile (.bashrc, .zshrc, etc.)
export VCPKG_ROOT=~/vcpkg
export PATH=$VCPKG_ROOT:$PATH
```

### Install Ninja (Optional but Recommended)

#### Windows
```powershell
# Using chocolatey
choco install ninja

# Or download from https://github.com/ninja-build/ninja/releases
```

#### Linux
```bash
# Ubuntu/Debian
sudo apt install ninja-build

# CentOS/RHEL
sudo yum install ninja-build

# Arch Linux
sudo pacman -S ninja
```

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone <your-repository-url> l2middlewares
cd l2middlewares
```

### 2. Install Dependencies

Dependencies are automatically managed by vcpkg. The project requires:
- **boost-asio** - Asynchronous networking
- **openssl** - Cryptographic functions
- **nlohmann-json** - JSON parsing (if needed)

vcpkg will automatically install these when you build the project.

## 🏗️ Build Instructions

The project uses CMake presets for easy building. You can build in Debug or Release mode.

### Option 1: Using CMake Presets (Recommended)

#### Debug Build
```bash
# Configure
cmake --preset debug

# Build everything
cmake --build --preset debug

# Or build specific components
cmake --build --preset login-debug    # Login server only
cmake --build --preset game-debug     # Game server only
cmake --build --preset core-debug     # Core library only
```

#### Release Build
```bash
# Configure
cmake --preset release

# Build everything
cmake --build --preset release

# Or build specific components
cmake --build --preset login-release  # Login server only
cmake --build --preset game-release   # Game server only
cmake --build --preset core-release   # Core library only
```

### Option 2: Manual CMake Build

```bash
# Create build directory
mkdir build && cd build

# Configure (Debug)
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake

# Or configure (Release)
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake

# Build
cmake --build . --parallel
```

### Build Outputs

After successful build, executables will be available in:
- `build/debug/out/` or `build/release/out/`
- `l2_login_server` - Login server executable
- `l2_game_server` - Game server executable

## 🎮 Running the Servers

### Login Server
```bash
./build/debug/out/l2_login_server
# or
./build/release/out/l2_login_server
```

### Game Server
```bash
./build/debug/out/l2_game_server
# or  
./build/release/out/l2_game_server
```

## 📁 Project Structure

```
src/
├── core/                          # Shared components
│   ├── encryption/               # RSA, Blowfish, XOR encryption
│   ├── network/                  # Base networking classes
│   ├── packets/                  # Base packet interfaces
│   └── utils/                    # Utilities (session keys, etc.)
├── login/                        # Login server
│   ├── server/                   # Server management
│   ├── network/                  # Login connection handling
│   ├── packets/                  # Login-specific packets
│   │   ├── requests/            # Client → Server packets
│   │   └── responses/           # Server → Client packets
│   └── data/                     # Data structures
└── game/                         # Game server
    ├── server/                   # Game server management
    ├── network/                  # Game connection handling
    └── packets/                  # Game-specific packets
        ├── requests/            # Client → Server packets
        └── responses/           # Server → Client packets
```

## 🔧 Development

### Adding New Packets

1. Create packet classes in `src/login/packets/` or `src/game/packets/`
2. Update the respective `PacketFactory`
3. Add handler methods in connection classes
4. Update `CMakeLists.txt` with new source files

### Key Files to Understand

- `src/login/network/login_client_connection.cpp` - Login client interactions
- `src/game/network/game_client_connection.cpp` - Game client interactions  
- `src/login/packets/packet_factory.cpp` - Login packet creation
- `src/game/packets/packet_factory.cpp` - Game packet creation

## 🐛 Troubleshooting

### Common Build Issues

1. **vcpkg not found**: Ensure `VCPKG_ROOT` environment variable is set
2. **Missing dependencies**: Run `vcpkg install` in project directory
3. **Compiler version**: Ensure C++20 support (GCC 10+, MSVC 2019+, Clang 12+)
4. **CMake version**: Requires CMake 3.21 or newer

### Runtime Issues

1. **Port conflicts**: Ensure ports 2106 (login) and 7777 (game) are available
2. **Encryption errors**: Check RSA key generation and client compatibility
3. **Connection issues**: Verify firewall settings

## 🤝 Contributing

This is just a Toy project, maybe if I'm able to make it work with basic features I will accept PRs!

