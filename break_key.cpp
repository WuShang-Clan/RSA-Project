// break_key.cpp - break the toy key by factoring n
#include <iostream>
#include <string>
#include "rsa.h"

int main()
{
    uint64 n = 1000036000099ULL;
    uint64 e = 65537;
    std::string ciphertext = "0614157364221 0502078796304 0031583460315";

    // 1. factor n by trial division
    uint64 p = 2;
    while (n % p != 0)
        p++;
    uint64 q = n / p;

    // 2. private key
    uint64 phi = (p - 1) * (q - 1);
    uint64 d = mod_inverse(e, phi);

    // 3. decrypt
    std::string message = decrypt_text(ciphertext, n, d);

    // 4. print
    std::cout << "p = " << p << std::endl;
    std::cout << "q = " << q << std::endl;
    std::cout << "Private key d = " << d << std::endl;
    std::cout << "Decrypted message: " << message << std::endl;

    return 0;
}
