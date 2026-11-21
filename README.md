# RSA Project (C++)

RSA encryption built from scratch in C++17 for **Discrete Structures, Fall 2026**.
Everything uses only `+ - * / %` on integers. No big-integer or cryptography
libraries (no `__int128`, `pow`, GMP, Boost or OpenSSL).

**Authors:** Name 1 (Roll No. ______) and Name 2 (Roll No. ______)

---

## Contents

- [How RSA works](#how-rsa-works)
- [Project files](#project-files)
- [Build and run](#build-and-run)
- [Sample output](#sample-output)
- [Function overview](#function-overview)
- [Error handling](#error-handling)
- [Breaking the toy key](#breaking-the-toy-key)
- [Running in Visual Studio](#running-in-visual-studio)
- [Sources](#sources)

---

## How RSA works

1. Pick two different primes `p` and `q`.
2. Compute `n = p * q` and `phi = (p - 1)(q - 1)`.
3. Pick `e` with `gcd(e, phi) = 1`.
4. Compute `d`, the inverse of `e` modulo `phi`.

The **public key** is `(n, e)` and the **private key** is `d`.

- Encrypt: `C = M^e mod n`
- Decrypt: `M = C^d mod n`

Letters are encoded as A = 00, B = 01, ..., Z = 25. Each block holds `k` letters,
where `k` is the largest number for which `2525...25` (k pairs) is less than `n`.
For `n = 2537`, `k = 2`, so "ST" becomes `18*100 + 19 = 1819`.

The scheme is secure only because factoring a large `n` is very hard. Our small
keys are for learning, not for protecting real data.

---

## Project files

| File | Purpose |
|---|---|
| `rsa.h` | Declarations of all RSA functions (B0 to B8) |
| `rsa.cpp` | Implementation of the RSA functions |
| `test_rsa.cpp` | Runs every test and prints `All tests passed` |
| `demo.cpp` | Interactive program: make keys, encrypt, decrypt |
| `break_key.cpp` | Breaks a small RSA key by factoring `n` |

---

## Build and run

You need `g++` with C++17 support.

**Tests**

    g++ -std=c++17 -O2 rsa.cpp test_rsa.cpp -o test_rsa
    ./test_rsa

**Demo**

    g++ -std=c++17 -O2 rsa.cpp demo.cpp -o demo
    ./demo

**Break the toy key**

    g++ -std=c++17 -O2 rsa.cpp break_key.cpp -o break_key
    ./break_key

On Windows Command Prompt, type `test_rsa`, `demo` and `break_key` without the `./`.

---

## Sample output

**Tests**

    All tests passed

**Demo** (input: `43 59 13`, then `Stop!`)

    Enter p q e: 43 59 13
    Public key: n = 2537, e = 13
    Private key: d = 937
    Block size: 2 letters
    Message: Stop!
    Cleaned: STOP
    Plaintext blocks: 1819 1415
    Ciphertext: 2081 2182
    Decrypted: STOP

If the keys are invalid, the demo prints the error and asks again:

    Enter p q e: 42 59 13
    Error: p and q must both be prime
    Enter p q e:

---

## Function overview

| ID | Function | What it does |
|---|---|---|
| B0 | `mul_mod(a, b, m)` | `(a * b) mod m` by repeated doubling, so it never overflows |
| B1 | `mod_exp(b, n, m)` | `b^n mod m` by fast exponentiation |
| B2 | `gcd(a, b)` | Euclidean algorithm |
| B3 | `extended_gcd(a, b, s, t)` | gcd and Bezout coefficients: `g = s*a + t*b` |
| B4 | `mod_inverse(a, m)` | Inverse of `a` modulo `m`, in the range `0 ... m-1` |
| B5 | `is_prime(n)` | Trial division, stopping when `d * d > n` |
| B6 | `generate_keys(p, q, e, n, d)` | Validates the input and builds `n` and `d` |
| B7 | `encrypt(M, n, e)` and `decrypt(C, n, d)` | RSA on a single number |
| B8 | `block_size(n)` | Number of letters per block |
| B8 | `encrypt_text(text, n, e)` | Text to ciphertext blocks |
| B8 | `decrypt_text(blocks, n, d)` | Ciphertext blocks back to text |

---

## Error handling

Errors are reported by throwing `std::invalid_argument` with a short message.

| Function | Throws when |
|---|---|
| `mod_inverse` | the gcd is not 1 (`"no inverse"`) |
| `generate_keys` | `p` or `q` is not prime, `p == q`, or `e` is invalid |
| `encrypt` / `decrypt` | the block is `>= n` |
| `block_size` | `n` is too small to hold even one letter |
| `decrypt_text` | a decrypted value is not a letter (wrong key) |

---

## Breaking the toy key

The published key is `n = 1000036000099`, `e = 65537`, with ciphertext
`0614157364221 0502078796304 0031583460315`.

`break_key.cpp` factors `n` by trial division, computes `phi`, finds the private
key with `mod_inverse`, and decrypts the message.

**Output of `break_key`:**

    p = 1000003
    q = 1000033
    Private key d = 983264276609
    Decrypted message: NUMBERTHEORYISFUNX

The final `X` is padding. The message is **NUMBER THEORY IS FUN**.

This attack works only because `n` is small: trial division takes about 10^6
steps here, but about 10^308 steps for a real 2048-bit key.

---

## Running in Visual Studio

Each program has its own `main`, so only one of `test_rsa.cpp`, `demo.cpp` and
`break_key.cpp` can be in the build at a time. Put all files in one project, set
the language standard to C++17, use the **Debug** configuration (so `assert`
works), and exclude the files you don't want to run. Then press Ctrl+F5.

---

## Sources

- Rosen, *Discrete Mathematics and Its Applications*, sections 4.1 to 4.4 and 4.6
- Course lecture slides on number theory for RSA
