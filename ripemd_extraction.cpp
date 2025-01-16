#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

// Function to split a line by a delimiter
std::vector<std::string> split(const std::string& line, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(line);
    std::string token;

    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

void extractRIPEMD160(const std::string& inputFilePath, const std::string& outputFilePath) {
    std::ifstream inputFile(inputFilePath);
    std::ofstream outputFile(outputFilePath);

    if (!inputFile.is_open()) {
        throw std::runtime_error("Failed to open input file: " + inputFilePath);
    }

    if (!outputFile.is_open()) {
        throw std::runtime_error("Failed to open output file: " + outputFilePath);
    }

    std::string line;
    size_t lineCount = 0;

    while (std::getline(inputFile, line)) {
        lineCount++;
        auto tokens = split(line, ',');

        // Ensure the line has the correct format
        if (tokens.size() != 3) {
            std::cerr << "Skipping malformed line " << lineCount << ": " << line << std::endl;
            continue;
        }

        // Extract compressed and uncompressed RIPEMD-160 hashes
        const std::string& compressedHash = tokens[1];
        const std::string& uncompressedHash = tokens[2];

        // Write hashes to the output file
        outputFile << compressedHash << std::endl;
        outputFile << uncompressedHash << std::endl;
    }

    inputFile.close();
    outputFile.close();

    std::cout << "RIPEMD-160 hashes extracted and saved to " << outputFilePath << std::endl;
}

int main() {
    try {
        const std::string inputFilePath = "FOUNDripmd.txt";
        const std::string outputFilePath = "ripgot.txt";

        extractRIPEMD160(inputFilePath, outputFilePath);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

