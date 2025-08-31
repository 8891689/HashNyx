# HashNyx

HashNyx is a high-performance, multi-threaded password hash cracker written in C. It is designed for flexibility and speed, utilizing various optimization techniques to efficiently find matches for given hash values.


# Features
Multi-threaded Architecture: Utilizes a producer-consumer model to maximize CPU utilization and separates password generation from hash verification.
1. Multiple Hash Algorithms: Supports common hash algorithms, currently limited to (more to come): MD5, SHA1, RIPEMD160, SM3, SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, Keccak224, Keccak256, Keccak384, Keccak512, and Hash160（BTC public key）.

2. Flexible Password Generation:
1. Sequential Mode: Generates all possible combinations for a given length range and character set.
2. Random Mode: Generates a specified number of random passwords.
3. Customizable Character Sets: Supports digits, uppercase, lowercase, special symbols, hex, or any combination.

3. Specialized Public Key Mode: A dedicated mode (-pub or -c pkc) for generating and testing candidates in the format of cryptographic public keys.

4. Performance Optimizations:
1. Single-Target Mode (-a): Ultra-fast checking against a single, hardcoded hash value.
2. Bloom Filter Support (-b): Uses a Bloom filter for rapid, probabilistic pre-screening to discard a vast majority of non-matching candidates before performing expensive final checks.

5. Real-time Status: A dedicated status thread provides live feedback on cracking speed (M/s) and total checked passwords.

# How It Works
HashNyx employs a producer-consumer architecture for efficient parallel processing:
1. Producer Threads (Cracker Threads): These threads are responsible for generating password candidates based on the specified mode (sequential or random), length, and character set.
2. Hashing & Pre-screening: Each generated candidate is hashed using the selected algorithm.
3. If Single-Target Mode (-a) is active, the hash is directly compared to the target.
4. If a Bloom Filter (-b) is provided, the hash is checked against it. Only hashes that might be in the target set (pass the filter) proceed. This is a major optimization.
5. Shared Queue: Candidates that pass the pre-screening phase (or if no pre-screening is used but a final check file -f is provided) are pushed into a thread-safe shared queue.
Consumer Thread (Verifier Thread): A dedicated thread pulls potential matches from the queue and performs a final, exact comparison against the full hash list loaded from the file specified by -f.
6. Status Thread: A separate, lightweight thread periodically calculates and prints the overall cracking progress and speed to stderr.
7. This design allows the password generation/hashing threads to run at full speed without being blocked by slower file I/O or final verification logic.
```
make
```
Clean and rebuild
```
make clean
```

# usage
```
./HashNyx -h
Usage: HashNyx [options]

Author: 8891689 (https://github.com/8891689)

Password Generation Options:
  -l <range>      Password length range (e.g., 8-10 or 8).
  -c <sets>       Charset, comma-separated (d,u,l,s,k,all,pkc).
                  d:digits, u:upper, l:lower, s:special, k:hex, all:all
                  pkc: public key mode (delegates to generator)
  -R              Enable random generation mode (default: sequential).
  -n <number>     Total number of passwords to generate in random mode (-R).
  -pub            Shortcut for public key generation mode.

Matching Options:
  -m <type>       Hash algorithm. Supports:
                  md5, sha1, ripemd160, hash160, sm3
                  sha224, sha256, sha384, sha512
                  sha3-224, sha3-256, sha3-384, sha3-512
                  keccak224, keccak256, keccak384, keccak512
                  (default: sha256)
  -a              Load a single hash value into the core for high-speed pre-screening.
  -b <file>       Load Bloom filter file for high-speed pre-screening.
  -f <file>       Load hash file for final (exact) check.

Output & Performance:
  -o <file>       Output found matches to a file (default: stdout).
  -t <num>        Number of cracker threads (producers) to use (default: 1).
  -bug            Debug mode, prints every generated hash.

Help:
  -h, --help      Show this help message.


Other commands:

bloom - Creates a Bloom filter from a hex-encoded hash list

gcc HashNyx_bloom.c bloom.c utils.c -O3 -o HashNyx_bloom -pthread -lm -static

cat hashes.txt | ./HashNyx_bloom   ,  type 1.txt | HashNyx_bloom.exe

```

Examples
1. Extremely Fast Single Hash Mode Sequential Cracking
Use a single thread to crack the hash values ​​of passwords between 5 and 9 characters in length.

```
./HashNyx -t 1 -l 5-9 -c d -m md5 -a 65f5a24d2b690cf3819e992cc20173e6
[+] Found matches will be written to default file: found.txt
[+] Single Target Mode enabled. Target hash: 65f5a24d2b690cf3819e992cc20173e6 (16 bytes)
[+] Starting cracker with 1 producer threads
[+] Generator: sequential
[+] Total combinations to generate: .
[!] Password: 45165, Hash: 65f5a24d2b690cf3819e992cc20173e6
[+] [19.0s] Checked: 442631880    | Speed: 24.13   M/s^C

or The random password needs to add -R

./HashNyx -t 1 -l 5-9 -c d -m sha1 -a 605c2fc5cad3abc98cff231c26857a9789a3d9e3
[+] Found matches will be written to default file: found.txt
[+] Single Target Mode enabled. Target hash: 605c2fc5cad3abc98cff231c26857a9789a3d9e3 (20 bytes)
[+] Starting cracker with 1 producer threads
[+] Generator: sequential
[+] Total combinations to generate: .
[!] Password: 023437, Hash: 605c2fc5cad3abc98cff231c26857a9789a3d9e3
[+] [18.0s] Checked: 317450784    | Speed: 18.60   M/s^C


or The random password needs to add -R

./HashNyx -t 1 -l 5-10 -c d -m ripemd160 -a 87cdfce3a4d1f07a1ca40c96ed000bcd7a4088c3
[+] Found matches will be written to default file: found.txt
[+] Single Target Mode enabled. Target hash: 87cdfce3a4d1f07a1ca40c96ed000bcd7a4088c3 (20 bytes)
[+] Starting cracker with 1 producer threads
[+] mode: 3, generator: sequential
[+] Total combinations to generate: .
[!] Password: 033120, Hash: 87cdfce3a4d1f07a1ca40c96ed000bcd7a4088c3
[+] [9.0s] Checked: 96942840     | Speed: 11.81   M/s^C

or

./HashNyx -t 1 -l 5-15 -c d -m sha256 -a 94b3a3cf52c846230d4c8c21c56e3e08c3bf5acd266b0422cc5bf7b97992c82c
[+] Found matches will be written to default file: found.txt
[+] Single Target Mode enabled. Target hash: 94b3a3cf52c846230d4c8c21c56e3e08c3bf5acd266b0422cc5bf7b97992c82c (32 bytes)
[+] Starting cracker with 1 producer threads
[+] Generator: sequential
[+] Total combinations to generate: .
[!] Password: 47389, Hash: 94b3a3cf52c846230d4c8c21c56e3e08c3bf5acd266b0422cc5bf7b97992c82c
[+] [15.0s] Checked: 170180672    | Speed: 12.36   M/s^C


```

2. Random Public Key Mode
Use one thread to generate incremental or random public key candidates, and then use HASH160 to match them with the given hash value. Incremental starts with:
020000000000000000000000000000000000000000000000000000000000000000
```
./HashNyx -t 1 -pub -m hash160 -a dad476f22458b934986e64577ca842311ff44e61
[+] Found matches will be written to default file: found.txt
[+] Single Target Mode enabled. Target hash: dad476f22458b934986e64577ca842311ff44e61 (20 bytes)
[+] Info: Public Key Generation Mode enabled.
[+] Starting cracker with 1 producer threads
[+] Generator: sequential
[+] Public Key Sequential Mode enabled.
[+] Total keys to generate: Infinite
[!] Password: 0200000000000000000000000000000000000000000000000000000000003ac83e, Hash: dad476f22458b934986e64577ca842311ff44e61
[+] [14.0s] Checked: 63000792     | Speed: 4.90    M/s^C


or 

./HashNyx -t 1 -c pkc -m hash160 -R -a dad476f22458b934986e64577ca842311ff44e61
[+] Found matches will be written to default file: found.txt
[+] Single Target Mode enabled. Target hash: dad476f22458b934986e64577ca842311ff44e61 (20 bytes)
[+] Info: Public Key Generation Mode enabled.
[+] Starting cracker with 1 producer threads
[+] Generator: random
[+] [17.0s] Checked: 69073344     | Speed: 4.36    M/s^C

```
3. Batch Hash Password Cracking Using a Bloom Filter
Use a pre-calculated Bloom filter (filter.bf) to quickly filter candidate results, then compare them to the complete list in 1.txt (check again before outputting to ensure 100% accuracy). This method is particularly effective when the search space is large.
```
./HashNyx -t 1 -l 5-9 -c d -m md5 -b targets.bf -f 1.txt -o 111.txt
[+] Found matches will be written to: 111.txt
[+] Bloom filter loaded: 537 bits, 13 hashes.
[+] Loading 28 hashes into memory for final verification...
[+] Finished loading hashes.
[+] Loaded 0 hashes for final verification.
[+] Starting 1 verification thread (consumer).
[+] Starting cracker with 1 producer threads
[+] Generator: sequential
[+] Total combinations to generate: .
[!] Password: 45165, Hash: 65f5a24d2b690cf3819e992cc20173e6
[!] Password: 45166, Hash: 5637435c4bcb65aed58744f24c8adaea
[!] Password: 04163646, Hash: ccb168657d7be7faee8699ae5d24a528
[!] Password: 39994081, Hash: 728b0ed58c213c2749886aafd27a6792
[!] Password: 63097448, Hash: 1154922366e1557a7f101ea9a15492cc
[!] Password: 95816510, Hash: eaee8b109574b03a037469edc918ed3e
[+] [17.0s] Checked: 170235648    | Speed: 11.96    M/s^C


The random password needs to add -R

./HashNyx -t 1 -l 5-9 -c d,s -R -m md5 -b targets.bf -f 1.txt -o 111.txt
[+] Found matches will be written to: 111.txt
[+] Bloom filter loaded: 537 bits, 13 hashes.
[+] Loading 28 hashes into memory for final verification...
[+] Finished loading hashes.
[+] Loaded 0 hashes for final verification.
[+] Starting 1 verification thread (consumer).
[+] Starting cracker with 1 producer threads
[+] Generator: random
[!] Password: 45165, Hash: 65f5a24d2b690cf3819e992cc20173e6
[+] [36.0s] Checked: 305823792    | Speed: 9.48    M/s^C

```
# Other ps 
```
d | 0123456789 [0-9]
l | abcdefghijklmnopqrstuvwxyz [a-z]
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ [A-Z]
k | 0123456789ABCDEF [0-9A-F]
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
all | abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"

-l <range>      Password length range (e.g., 8-10 or 8).
-c <sets>       Charset, comma-separated (d,u,l,s,k,all,pkc).

d:digits, 
u:upper, 
l:lower, 
s:special, 
k:hex, 
all:all
pkc: public key mode (same as -pub)
```
You can use to separate the character sets needed for password cracking, such as numbers, uppercase letters -c d,u or all -c all

Note that the generator will generate passwords longer than 13 characters, requiring -R, except for public keys, as the increment would exceed the count limit.

# Bloom Controller

For example, load the Hasselblad value in 1.txt into the Bloomer targets.bf
```
cat 1.txt | ./HashNyx_bloom
Processing 28 hashes with a target false positive rate of 0.0100%
Optimal parameters calculated:
 - Bit count (m): 537
 - Hash functions (k): 13
Successfully added 28 hashes to Bloom filter.
Bloom filter successfully saved to targets.bf (Size: 0.00 MB)

```

# windows platform
For example, load the Hasselblad value in 1.txt into the Bloomer targets.bf
```
type 1.txt | HashNyx_bloom.exe
Processing 28 hashes with a target false positive rate of 0.0100%
Optimal parameters calculated:
 - Bit count (m): 537
 - Hash functions (k): 13
Successfully added 28 hashes to Bloom filter.
Bloom filter successfully saved to targets.bf (Size: 0.00 MB)
```

# Thank you for your help
```
gemini deepseek
```

# Sponsorship
If this project has been helpful or inspiring, please consider buying me a coffee. Your support is greatly appreciated. Thank you!

```
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k

ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1

DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky

TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4

```
# ⚠️ Disclaimer

1. Disclaimer: This tool is intended to help developers gain a deeper understanding of its workings and is for mutual learning and research purposes only.
2. Please understand the associated risks before using this tool. Decrypting someone else's private key is unethical and illegal. Please comply with local laws and regulations! Do not use this tool for any illegal purposes; you will be solely responsible for the consequences.
3. The developer is not responsible for any indirect or direct financial losses or legal liabilities resulting from the use of this tool.
