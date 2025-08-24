# HashNyx

HashNyx is a high-performance, multi-threaded password hash cracker written in C. It is designed for flexibility and speed, utilizing various optimization techniques to efficiently find matches for given hash values.


# Features
Multi-threaded Architecture: Utilizes a producer-consumer model to maximize CPU usage, separating password generation from hash verification.
1. Multiple Hash Algorithms: Supports common hashing algorithms including md5, sha1, sha256, ripemd160, keccak256, and hash160.

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
  -m <type>       Hash algorithm. Supports: md5, sha1, sha256, ripemd160, keccak256, hash160.
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

Testing and Verification

Based on Intel® Xeon® E5-2697 v4 2.30 GHz single-threaded environment

1. Extremely Fast Single Hash Mode Sequential Cracking
Use a single thread to crack the hash values ​​of passwords between 5 and 10 characters in length.

```
./HashNyx -t 1 -l 5-10 -c d -m sha256 -a 94b3a3cf52c846230d4c8c21c56e3e08c3bf5acd266b0422cc5bf7b97992c82c
[+] Found matches will be written to default file: found.txt
[+] Single Target Mode enabled. Target hash: 94b3a3cf52c846230d4c8c21c56e3e08c3bf5acd266b0422cc5bf7b97992c82c (32 bytes)
[+] Starting cracker with 1 producer threads
[+] mode: 2, generator: sequential
[+] Total combinations to generate: .
[!] Password: 47389, Hash: 94b3a3cf52c846230d4c8c21c56e3e08c3bf5acd266b0422cc5bf7b97992c82c
[+] [4.0s] Checked: 44590752     | Speed: 11.12   M/s^C

or The random password needs to add -R

./HashNyx -t 1 -l 5-10 -c d -m ripemd160 -a 87cdfce3a4d1f07a1ca40c96ed000bcd7a4088c3
[+] Found matches will be written to default file: found.txt
[+] Single Target Mode enabled. Target hash: 87cdfce3a4d1f07a1ca40c96ed000bcd7a4088c3 (20 bytes)
[+] Starting cracker with 1 producer threads
[+] mode: 3, generator: sequential
[+] Total combinations to generate: .
[!] Password: 033120, Hash: 87cdfce3a4d1f07a1ca40c96ed000bcd7a4088c3
[+] [9.0s] Checked: 96942840     | Speed: 10.81   M/s^C

or

./HashNyx -t 1 -l 5-7 -c d -m md5 -a 3af7a3caf8d2fe05aaf020bdb06f833c
[+] Found matches will be written to default file: found.txt
[+] Single Target Mode enabled. Target hash: 3af7a3caf8d2fe05aaf020bdb06f833c (16 bytes)
[+] Starting cracker with 1 producer threads
[+] mode: 0, generator: sequential
[+] Total combinations to generate: .
[!] Password: 45171, Hash: 3af7a3caf8d2fe05aaf020bdb06f833c
[+] [2.0s] Checked: 11100000     | Speed: 5.22    M/s

[+] Cracking finished in 2.00 seconds.
[+] Total passwords checked: 11100000 (5.55 M/s avg).

```

2. Random Public Key Mode
Use one thread to generate random public key candidates, which are then matched against a given hash using HASH160.
```
./HashNyx -pub -m hash160 -a 15f508024c86f95c75aa439a47e9230d9a990421
[+] Found matches will be written to default file: found.txt
[+] Single Target Mode enabled. Target hash: 15f508024c86f95c75aa439a47e9230d9a990421 (20 bytes)
[+] Info: Public Key Generation Mode enabled.
[!] Warning: Public key mode requires random generation. Forcing -R mode.
[+] Starting cracker with 1 producer threads
[+] mode: 5, generator: random
[+] [5.0s] Checked: 19317848     | Speed: 3.87    M/s^C

or 

./HashNyx -t 1 -c pkc -m hash160 -a 15f508024c86f95c75aa439a47e9230d9a990421
[+] Found matches will be written to default file: found.txt
[+] Single Target Mode enabled. Target hash: 15f508024c86f95c75aa439a47e9230d9a990421 (20 bytes)
[+] Info: Public Key Generation Mode enabled.
[!] Warning: Public key mode requires random generation. Forcing -R mode.
[+] Starting cracker with 1 producer threads
[+] mode: 5, generator: random
[+] [8.0s] Checked: 30994056     | Speed: 3.88    M/s^C


```
3. Batch Hash Password Cracking Using a Bloom Filter
Use a pre-calculated Bloom filter (filter.bf) to quickly filter candidate results, then compare them to the complete list in 1.txt (check again before outputting to ensure 100% accuracy). This method is particularly effective when the search space is large.
```
 ./HashNyx -t 1 -l 5-9 -c d -m sha256 -b targets.bf -f 1.txt -o 111.txt
[+] Found matches will be written to: 111.txt
[+] Bloom filter loaded: 671 bits, 13 hashes.
[+] Loading 35 hashes into memory for final verification...
[+] Finished loading hashes.
[+] Loaded 0 hashes for final verification.
[+] Starting 1 verification thread (consumer).
[+] Starting cracker with 1 producer threads
[+] mode: 2, generator: sequential
[+] Total combinations to generate: .
[!] Password: 47379, Hash: 2ba19b8d43574d5d545e836b2c282806c4fd0bcfeeb5360de08f57b6232ea5a9
[!] Password: 47380, Hash: 7715d264ad95af873da6f7cd84cebf8d0da687f662d7444936ad09a9c3ea1739
[!] Password: 47381, Hash: c020e7068f3cc7e8733d286749c03ac63d15b624786865e21f03caf3d49a9231
[!] Password: 47382, Hash: abc59f3af863dabf938977dd0298a98cd515661310f2fca0e5dc31e7740b22b1
[!] Password: 47383, Hash: 54c59efe0efcbd2bcfa25735d200e981d2565aac34b89c08341736ee189fc6e0
[!] Password: 47384, Hash: 7778eff31c1cf5d8b27e8e1c2ef6e5b8b2b5d45b96b03951845808f490a09001
[!] Password: 47385, Hash: 4c10852df386a579cf956c19aed0b10b9103e9eac0978bfe2ed5dfe27c1e7dee
[!] Password: 47386, Hash: 42ed571f9af2962980de8cf2f583e42001acc2ab4d3ab4caa0578d215c3caa5c
[!] Password: 47387, Hash: 79950794d1a45563a2f2cdf0e9d8266ae3a8894bfbc189e6e7f92100ccfb807a
[!] Password: 47388, Hash: 2bf6f38b99745b94d48562cdc1dc1e9eefb20e5620d6a48b235465a0992f3355
[!] Password: 47389, Hash: 94b3a3cf52c846230d4c8c21c56e3e08c3bf5acd266b0422cc5bf7b97992c82c
[+] [3.0s] Checked: 15812248     | Speed: 5.27    M/s^C

to

./HashNyx -t 1 -l 5-9 -c d -m hash160 -b targets.bf -f 1.txt -o 111.txt
[+] Found matches will be written to: 111.txt
[+] Bloom filter loaded: 671 bits, 13 hashes.
[+] Loading 35 hashes into memory for final verification...
[+] Finished loading hashes.
[+] Loaded 0 hashes for final verification.
[+] Starting 1 verification thread (consumer).
[+] Starting cracker with 1 producer threads
[+] mode: 5, generator: sequential
[+] Total combinations to generate: .
[!] Password: 023286, Hash: 242f8a33453eb3d2b101cec9c938ac70cac340a4
[!] Password: 023287, Hash: e3a018fb78ea8f91b1682e8983ce9b47a0b9424c
[+] [5.0s] Checked: 20476656     | Speed: 4.10    M/s^C

The random password needs to add -R

./HashNyx -t 1 -l 5-9 -c d -R -m hash160 -b targets.bf -f 1.txt -o 111.txt
[+] Found matches will be written to: 111.txt
[+] Bloom filter loaded: 671 bits, 13 hashes.
[+] Loading 35 hashes into memory for final verification...
[+] Finished loading hashes.
[+] Loaded 0 hashes for final verification.
[+] Starting 1 verification thread (consumer).
[+] Starting cracker with 1 producer threads
[+] mode: 5, generator: random
[!] Password: 023287, Hash: e3a018fb78ea8f91b1682e8983ce9b47a0b9424c
[+] [2.0s] Checked: 7537368      | Speed: 3.79    M/s^C

```
# Other ps 
```
d | 0123456789 [0-9]
l | abcdefghijklmnopqrstuvwxyz [a-z]
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ [A-Z]
k | 0123456789ABCDEF [0-9A-F]
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
all | abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"
```
```
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

Note that the generator will produce passwords longer than 13 characters, requiring -R, as the increment would exceed the count limit.

# Bloom Controller

For example, load the Hasselblad value in 1.txt into the Bloomer targets.bf
```
cat 1.txt | ./HashNyx_bloom
Processing 35 hashes with a target false positive rate of 0.0100%
Optimal parameters calculated:
 - Bit count (m): 671
 - Hash functions (k): 13
Successfully added 35 hashes to Bloom filter.
Bloom filter successfully saved to targets.bf (Size: 0.00 MB)
```

# windows platform
For example, load the Hasselblad value in 1.txt into the Bloomer targets.bf
```
type 1.txt | HashNyx_bloom.exe

Processing 35 hashes with a target false positive rate of 0.0100%
Optimal parameters calculated:
 - Bit count (m): 671
 - Hash functions (k): 13
Successfully added 35 hashes to Bloom filter.
Bloom filter successfully saved to targets.bf (Size: 0.00 MB)
```

# Thanks
```
gemini deep seek
```

# Sponsorship
If this project has been helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!

```
-BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k

ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1

DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky

TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4

```
# ⚠️ # Disclaimer

1. This tool is intended to help developers gain a deeper understanding of its workings and is for learning and research purposes only. 
2. Please use it after understanding the associated risks and comply with local laws and regulations.
3. The developer is not responsible for any indirect or direct financial losses or legal liabilities resulting from the use of this tool.

