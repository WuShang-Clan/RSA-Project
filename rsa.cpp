// Part B, B0 to B8

#include "rsa.h"
#include <vector>
#include <cctype>   // isalpha, toupper

// B0: (a * b) mod m by repeated doubling, so nothing overflows
uint64 mul_mod(uint64 a, uint64 b, uint64 m)
{
    a = a % m;
    b = b % m;
    uint64 result = 0;

    while (b > 0)
    {
        if (b % 2 == 1)                 // last bit of b is 1
            result = (result + a) % m;
        a = (a + a) % m;                // a doubles
        b = b / 2;                      // drop the last bit of b
    }
    return result;
}

// B1:b^n mod m (Rosen's Algorithm 5)
uint64 mod_exp(uint64 b, uint64 n, uint64 m)
{
    uint64 x = 1 % m;       // so that m = 1 gives 0
    uint64 power = b % m;

    while (n > 0)
    {
        if (n % 2 == 1)                 // last bit of n is 1
            x = mul_mod(x, power, m);
        power = mul_mod(power, power, m);
        n = n / 2;
    }
    return x;
}

// B2:Euclidean algorithm
uint64 gcd(uint64 a, uint64 b)
{
    while (b != 0)
    {
        uint64 r = a % b;
        a = b;
        b = r;
    }
    return a;
}

// B3: extended Euclid: g = s*a + t*b
long long extended_gcd(long long a, long long b, long long& s, long long& t)
{
    // Step 1: divide forward
    vector<long long> quotients;
    long long r0 = a;
    long long r1 = b;

    while (r1 != 0)
    {
        quotients.push_back(r0 / r1);
        long long r2 = r0 % r1;
        r0 = r1;
        r1 = r2;
    }
    long long g = r0;       // r0 is now the gcd

    // Step 2: substitute backward (g = 1*g + 0*0 at the start)
    long long x = 1;
    long long y = 0;

    for (int i = (int)quotients.size() - 1; i >= 0; i--)
    {
        long long q = quotients[i];
        long long new_x = y;
        long long new_y = x - q * y;
        x = new_x;
        y = new_y;
    }

    s = x;
    t = y;
    return g;
}

// B4:inverse of a modulo m, in the range 0 ... m-1
uint64 mod_inverse(uint64 a, uint64 m)
{
    long long s, t;
    long long g = extended_gcd((long long)a, (long long)m, s, t);

    if (g != 1)
        throw invalid_argument("no inverse");

    // s may be negative, so cast m to long long before using %
    long long r = s % (long long)m;
    if (r < 0)
        r += (long long)m;

    return (uint64)r;
}

// B5:trial division
bool is_prime(uint64 n)
{
    if (n < 2)
        return false;

    // d <= n / d means the same as d*d <= n, but cannot overflow
    for (uint64 d = 2; d <= n / d; d++)
    {
        if (n % d == 0)
            return false;
    }
    return true;
}

// B6:build the keys from p, q and e
void generate_keys(uint64 p, uint64 q, uint64 e, uint64& n, uint64& d)
{
    if (!is_prime(p) || !is_prime(q))
        throw invalid_argument("p and q must both be prime");

    if (p == q)
        throw invalid_argument("p and q must be different");

    uint64 phi = (p - 1) * (q - 1);

    if (e <= 1 || e >= phi || gcd(e, phi) != 1)
        throw invalid_argument("e must satisfy 1 < e < (p-1)(q-1) and gcd(e, (p-1)(q-1)) = 1");

    n = p * q;
    d = mod_inverse(e, phi);
}

// B7:encrypt and decrypt one number
uint64 encrypt(uint64 M, uint64 n, uint64 e)
{
    if (M >= n)
        throw invalid_argument("message block must be less than n");
    return mod_exp(M, e, n);
}

uint64 decrypt(uint64 C, uint64 n, uint64 d)
{
    if (C >= n)
        throw invalid_argument("ciphertext block must be less than n");
    return mod_exp(C, d, n);
}

// B8:text encryption
int block_size(uint64 n)
{
    uint64 z = 25;
    if (z >= n)
        throw invalid_argument("n is too small to hold even one letter");

    int k = 1;
    while (k < 9)
    {
        uint64 next = z * 100 + 25;
        if (next >= n)
            break;
        z = next;
        k++;
    }
    return k;
}

string encrypt_text(const string& text, uint64 n, uint64 e)
{
    int k = block_size(n);

    // 1.keep only letters, make them upper case
    string clean = "";
    for (int i = 0; i < (int)text.length(); i++)
    {
        if (isalpha((unsigned char)text[i]))
            clean += (char)toupper((unsigned char)text[i]);
    }

    // 2.pad with X until the length is a multiple of k
    while ((int)clean.length() % k != 0)
        clean += 'X';

    int width = (int)to_string(n).length();   // digits in n
    string result = "";

    // 3.go through the text, k letters at a time
    for (int start = 0; start < (int)clean.length(); start += k)
    {
        uint64 M = 0;
        for (int j = 0; j < k; j++)
            M = M * 100 + (uint64)(clean[start + j] - 'A');

        // 4.encrypt the block
        uint64 C = encrypt(M, n, e);

        // 5.write C with leading zeros
        string digits = to_string(C);
        while ((int)digits.length() < width)
            digits = "0" + digits;

        // 6) blocks separated by single spaces
        if (start > 0)
            result += " ";
        result += digits;
    }
    return result;
}

string decrypt_text(const string& blocks, uint64 n, uint64 d)
{
    int k = block_size(n);
    string result = "";
    uint64 num = 0;
    bool have_digits = false;  // true while we are inside a number

    // go one character further than the string so the last number is processed
    for (int i = 0; i <= (int)blocks.length(); i++)
    {
        if (i < (int)blocks.length() && blocks[i] >= '0' && blocks[i] <= '9')
        {
            num = num * 10 + (uint64)(blocks[i] - '0');
            have_digits = true;
        }
        else
        {
            //space (or end of string): the number is complete
            if (have_digits)
            {
                // 2.decrypt
                uint64 M = decrypt(num, n, d);

                // 3)turn M back into k letters, right to left
                string letters = "";
                for (int j = 0; j < k; j++)
                {
                    uint64 value = M % 100;
                    if (value > 25)
                        throw invalid_argument("bad letter value: wrong key?");
                    // the new letter goes at the FRONT (we work right to left)
                    letters = (char)('A' + value) + letters;
                    M = M / 100;
                }
                result += letters;
            }
            num = 0;
            have_digits = false;
        }
    }
    return result;
}