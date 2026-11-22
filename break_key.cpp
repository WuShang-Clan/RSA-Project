#include <iostream>
#include <string>
#include "rsa.h"

int main()
{
    uint64 n = 1000036000099ULL;
    uint64 e = 65537;
    string ciphertext = "0614157364221 0502078796304 0031583460315";

    // 1.factor n by trial division
    uint64 p = 2;
    while (n % p != 0)
        p++;
    uint64 q = n / p;

    // 2.)private key
    uint64 phi = (p - 1) * (q - 1);
    uint64 d = mod_inverse(e, phi);

    // 3) decrypt
    string message = decrypt_text(ciphertext, n, d);

    // 4.print
    cout << "p = " << p << endl;
    cout << "q = " << q << endl;
    cout << "Private key d = " << d << endl;
    cout << "Decrypted message: " << message << endl;

    return 0;
}