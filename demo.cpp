// demo.cpp - interactive RSA demo
#include <iostream>
#include <string>
#include <cctype>
#include "rsa.h"

int main()
{
    uint64 p, q, e, n, d;

    // 1. keep asking until generate_keys accepts the input
    while (true)
    {
        std::cout << "Enter p q e: ";
        if (!(std::cin >> p >> q >> e))
        {
            std::cout << "Please type three numbers." << std::endl;
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }
        try
        {
            generate_keys(p, q, e, n, d);
            break;      // success
        }
        catch (const std::invalid_argument &ex)
        {
            std::cout << "Error: " << ex.what() << std::endl;
        }
    }

    // 2. print the keys
    int k = block_size(n);
    std::cout << "Public key: n = " << n << ", e = " << e << std::endl;
    std::cout << "Private key: d = " << d << std::endl;
    std::cout << "Block size: " << k << " letters" << std::endl;

    // 3. read the message (skip the rest of the line first)
    std::cin.ignore(10000, '\n');
    std::cout << "Message: ";
    std::string message;
    std::getline(std::cin, message);

    // 4. cleaned message (letters only, upper case, padded with X)
    std::string cleaned = "";
    for (size_t i = 0; i < message.length(); i++)
    {
        if (isalpha((unsigned char)message[i]))
            cleaned += (char)toupper((unsigned char)message[i]);
    }
    while (cleaned.length() % k != 0)
        cleaned += 'X';
    std::cout << "Cleaned: " << cleaned << std::endl;

    // plaintext numbers M
    std::cout << "Plaintext blocks:";
    for (size_t start = 0; start < cleaned.length(); start += k)
    {
        uint64 M = 0;
        for (int j = 0; j < k; j++)
            M = M * 100 + (uint64)(cleaned[start + j] - 'A');
        std::cout << " " << M;
    }
    std::cout << std::endl;

    // ciphertext
    std::string cipher = encrypt_text(message, n, e);
    std::cout << "Ciphertext: " << cipher << std::endl;

    // 5. decrypt
    std::cout << "Decrypted: " << decrypt_text(cipher, n, d) << std::endl;

    return 0;
}
