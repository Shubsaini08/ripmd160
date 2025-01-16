#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <random>
#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

constexpr size_t PRIVATE_KEY_SIZE = 32;  // 32 bytes for secp256k1 private keys
constexpr char OUTPUT_FILE[] = "FOUNDripmd.txt";
constexpr size_t STATS_INTERVAL_MS = 1000;

std::atomic<size_t> totalKeysGenerated(0);
std::atomic<size_t> keysGeneratedLastInterval(0);
std::mutex outputMutex;
std::atomic<bool> running(true);

class KeyProcessor {
private:
    std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)> ctx;

public:
    KeyProcessor() : ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN), &secp256k1_context_destroy) {
        if (!ctx) {
            throw std::runtime_error("Failed to initialize secp256k1 context");
        }
    }

    std::vector<unsigned char> generateCompressedPublicKey(const std::vector<unsigned char>& privateKey) {
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx.get(), &pubkey, privateKey.data())) {
            throw std::runtime_error("Failed to create public key");
        }

        unsigned char output[33];
        size_t outputLen = sizeof(output);
        secp256k1_ec_pubkey_serialize(ctx.get(), output, &outputLen, &pubkey, SECP256K1_EC_COMPRESSED);

        return std::vector<unsigned char>(output, output + outputLen);
    }

    std::vector<unsigned char> generateUncompressedPublicKey(const std::vector<unsigned char>& privateKey) {
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx.get(), &pubkey, privateKey.data())) {
            throw std::runtime_error("Failed to create public key");
        }

        unsigned char output[65];
        size_t outputLen = sizeof(output);
        secp256k1_ec_pubkey_serialize(ctx.get(), output, &outputLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

        return std::vector<unsigned char>(output, output + outputLen);
    }

    std::vector<unsigned char> sha256(const std::vector<unsigned char>& input) {
        std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
        SHA256(input.data(), input.size(), hash.data());
        return hash;
    }

    std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& input) {
        std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
        RIPEMD160(input.data(), input.size(), hash.data());
        return hash;
    }

    std::string toHexString(const std::vector<unsigned char>& input) {
        std::ostringstream oss;
        for (const auto& byte : input) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return oss.str();
    }
};

std::vector<unsigned char> generateRandomKey(std::mt19937_64& rng) {
    std::vector<unsigned char> key(PRIVATE_KEY_SIZE);
    for (size_t i = 0; i < PRIVATE_KEY_SIZE; ++i) {
        key[i] = static_cast<unsigned char>(rng() & 0xFF);
    }
    return key;
}

void saveKeyData(std::ofstream& outFile, const std::string& privateKeyHex, const std::string& compressedHash, const std::string& uncompressedHash) {
    std::lock_guard<std::mutex> lock(outputMutex);
    outFile << privateKeyHex << "," << compressedHash << "," << uncompressedHash << std::endl;
}

void processKeys(size_t keysPerThread) {
    KeyProcessor processor;
    std::mt19937_64 rng(std::random_device{}());

    std::ofstream outFile(OUTPUT_FILE, std::ios::app);
    if (!outFile.is_open()) {
        throw std::runtime_error("Failed to open output file");
    }

    for (size_t i = 0; i < keysPerThread && running.load(); ++i) {
        auto privateKey = generateRandomKey(rng);
        auto compressedKey = processor.generateCompressedPublicKey(privateKey);
        auto uncompressedKey = processor.generateUncompressedPublicKey(privateKey);

        auto compressedHash = processor.ripemd160(processor.sha256(compressedKey));
        auto uncompressedHash = processor.ripemd160(processor.sha256(uncompressedKey));

        std::string privateKeyHex = processor.toHexString(privateKey);
        std::string compressedHashHex = processor.toHexString(compressedHash);
        std::string uncompressedHashHex = processor.toHexString(uncompressedHash);

        saveKeyData(outFile, privateKeyHex, compressedHashHex, uncompressedHashHex);

        keysGeneratedLastInterval++;
        totalKeysGenerated++;
    }
}

void displayStats() {
    while (running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(STATS_INTERVAL_MS));

        size_t keysInInterval = keysGeneratedLastInterval.exchange(0);
        size_t totalKeys = totalKeysGenerated.load();

        std::cout << "####################################################" << std::endl;
        std::cout << "[X] GENERATED KEYS :: " << keysInInterval << " keys/s" << std::endl;
        std::cout << "[X] TOTAL KEYS EVER GENERATED :: " << totalKeys << std::endl;
        std::cout << "[X] SAVED OUTPUTS WILL BE SAVED INTO " << OUTPUT_FILE << std::endl;
    }
}

int main() {
    try {
        size_t threads = std::thread::hardware_concurrency();
        if (threads == 0) threads = 8;

        size_t keysPerThread = 100000000000000000000000000000000000000000000000000000000000;  // Number of keys per thread

        std::vector<std::thread> workers;
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back(processKeys, keysPerThread);
        }

        std::thread statsThread(displayStats);

        for (auto& worker : workers) {
            worker.join();
        }

        running.store(false);
        statsThread.join();

        std::cout << "Key generation completed." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
