#include <iostream>
#include <string>
#include <cctype>
#include "rsa.h"

int main()
{
    uint64 p, q, e, n, d;

    // 1.keep asking until generate_keys accepts the input
    while (true)
    {
        cout << "Enter p q e: ";
        if (!(cin >> p >> q >> e))
        {
            cout << "Please type three numbers." << endl;
            cin.clear();
            cin.ignore(10000, '\n');
            continue;
        }
        try
        {
            generate_keys(p, q, e, n, d);
            break;      // success
        }
        catch (const invalid_argument& ex)
        {
            cout << "Error: " << ex.what() << endl;
        }
    }

    // 2)print the keys
    int k = block_size(n);
    cout << "Public key: n = " << n << ", e = " << e << endl;
    cout << "Private key: d = " << d << endl;
    cout << "Block size: " << k << " letters" << endl;

    // 3) read the message (skip the rest of the line first)
    cin.ignore(10000, '\n');
    cout << "Message: ";
    string message;
    getline(cin, message);

    // 4 cleaned message (letters only, upper case, padded with X)
    string cleaned = "";
    for (int i = 0; i < (int)message.length(); i++)
    {
        if (isalpha((unsigned char)message[i]))
            cleaned += (char)toupper((unsigned char)message[i]);
    }
    while ((int)cleaned.length() % k != 0)
        cleaned += 'X';
    cout << "Cleaned: " << cleaned << endl;

    // plaintext numbers M
    cout << "Plaintext blocks:";
    for (int start = 0; start < (int)cleaned.length(); start += k)
    {
        uint64 M = 0;
        for (int j = 0; j < k; j++)
            M = M * 100 + (uint64)(cleaned[start + j] - 'A');
        cout << " " << M;
    }
    cout << endl;

    // ciphertext
    string cipher = encrypt_text(message, n, e);
    cout << "Ciphertext: " << cipher << endl;

    // 5. decrypt
    cout << "Decrypted: " << decrypt_text(cipher, n, d) << endl;

    return 0;
}