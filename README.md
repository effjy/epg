# Entropy Password Generator (EPG) (Diceware)

[![C](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-CSPRNG-brightgreen.svg)](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

**EPG** is a command‑line password/passphrase generator written in C with **cryptographically secure randomness**, unbiased selection, and dynamic entropy calculation.  
It offers two distinct modes:

- **Diceware mode** – generates a memorable passphrase from the original 7776‑word Diceware list, with random printable separators between words (e.g. `lift{palm<lie+meaty.bert:zoe<impel_q's`).  
- **Random character mode** – generates a fully random ASCII password of a precise length (e.g. 64 characters = ~420 bits of entropy).

Both modes calculate and display the **actual entropy** (in bits) based on the loaded wordlist size or character set.  
The program sanitises all sensitive memory before exit.

---

## 🔐 Security Highlights

- **Cryptographically secure RNG** – reads directly from `/dev/urandom` (Linux/Unix).  
- **No modulo bias** – uses 32‑bit rejection sampling for perfectly unbiased indices, even with wordlists larger than 256 entries.  
- **Dynamic entropy** – `log2(word_count)` per word, not a hard‑coded constant.  
- **Safe input parsing** – `strtol` with full error checking, no `atoi()`.  
- **Memory sanitisation** – all temporary buffers and wordlist strings are zeroed before `free()`.  
- **Single‑Enter UX** – after generating a password, press `Enter` once to return to the main menu.

---

## 📦 Requirements

- A **C compiler** (GCC, Clang, etc.)  
- The **Diceware wordlist** – `diceware.wordlist.asc` in the same directory as the executable.  
- `libm` (math library) – for `log2()`.

### Getting the official Diceware wordlist

You can download the original wordlist from the [official Diceware page](https://diceware.com) or directly from GitHub:

```bash
wget https://raw.githubusercontent.com/ylixir/diceware/master/diceware.wordlist.asc
```

The file must contain lines like:

```
11111	a
11112	a&p
11113	a's
...
```

(only digits, a space or tab, and the word – no extra headers or PGP signatures).

---

## ⚙️ Compilation

```bash
gcc -o epg epg.c -Wall -Wextra -O2 -lm
```

The `-lm` flag links the math library (required for `log2`). No other external dependencies are needed.

---

## 🚀 Usage

1. Place `diceware.wordlist.asc` in the same folder as `epg`.  
2. Run `./epg`.  
3. Use the interactive menu:

```
=== Entropy Password Generator ===
1. Generate password
2. Settings
3. Exit (sanitize memory)
Choice: 
```

### Settings

- **Toggle mode** – switch between *Diceware (words)* and *Random characters*.  
- **Adjust strength**  
  - In Diceware mode: set the number of words (default 8, min 4, max 20).  
  - In Random mode: set the exact length (default 64, min 8, max 512).  

The current entropy value (in bits) is displayed next to each setting.

### Generating a password

- **Diceware mode** – outputs a passphrase like:  
  `yaw!lao!defog!upend!bald!nub!trip!whisky`  
  Shows the number of words, the resulting string length, and the entropy (e.g., 8 words ≈ 103 bits).  
- **Random mode** – outputs a fully random password, e.g.:  
  `gT6&kL9$mN2#qR8*XvB5@wP7`  
  with the exact length and entropy (≈6.55 bits per character).

Press **Enter** once to return to the main menu after viewing the password.

---

## 📝 Example session

```text
Loaded 7776 Diceware words.

=== Entropy Password Generator ===
1. Generate password
2. Settings
3. Exit (sanitize memory)
Choice: 2

=== Password Settings ===
1. Toggle mode: Diceware (words)
2. Set number of words (current: 8) [entropy: 103.4 bits]
3. Return to main menu
Choice: 2
Enter number of words: 6

Will use 6 words (≈ 77.6 bits entropy).

=== Password Settings ===
1. Toggle mode: Diceware (words)
2. Set number of words (current: 6) [entropy: 77.6 bits]
3. Return to main menu
Choice: 3

=== Entropy Password Generator ===
1. Generate password
2. Settings
3. Exit (sanitize memory)
Choice: 1

--- Diceware Passphrase (6 words, entropy ≈ 77.6 bits) ---
Password length: 41 characters
yaw!lao!defog!upend!bald!nub

Press Enter to continue...
```

---

## 🛡️ Why this matters

- **8‑word Diceware** (≈103 bits) is already resistant to any brute‑force attack, even with fast hashes.  
- **Random‑char mode with 64 characters** gives ≈420 bits – astronomically secure.  
- Using a CSPRNG + unbiased selection guarantees that the generated secrets have the full entropy you expect.  
- The program is **self‑contained**, auditable, and trivial to compile – no external crypto libraries required.

---

## 📄 License

MIT License – see the [LICENSE](LICENSE) file (or feel free to reuse the code under the MIT terms).

---

## 🙏 Acknowledgements

- Diceware wordlist by Arnold Reinhold ([diceware.com](https://diceware.com)).  
- Inspired by the need for a simple, transparent, entropy‑aware password generator that gets the randomness right.
```
