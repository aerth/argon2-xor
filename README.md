# argon2-xor

simple XOR stream with HMAC and random salt

Using the variable output length of the Argon2id hash function, we are able to derive a key to use with XOR stream cipher.

We generate a random salt, Encrypt-then-MAC, and save to a file (or stdout).

To decrypt, we extract the salt and MAC, hash the password (with given salt), and XOR the rest of the file.

Note: This is a toy program, and hasn't been vetted by cryptographers or security professionals.
