# Entropy Password Generator (EPG) (Diceware)

[![C](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

**EPG** is a command‑line password/passphrase generator written in C.  
It supports two distinct modes:

- **Diceware mode** – generates a memorable passphrase from a true Diceware wordlist, with random separators (e.g. `lift{palm<lie+meaty.bert:zoe<impel_q's`).  
- **Random character mode** – generates a fully random printable ASCII password of a precise length (e.g. 64 characters, ~420 bits of entropy).

Both modes calculate and display the entropy (in bits) of the generated secret.  
The program also sanitises sensitive memory on exit.

---

## Features

- **Diceware** – uses the original 7776‑word Diceware list (`diceware.wordlist.asc`).  
- **Configurable strength** – choose exactly how many words (4–20) or how many random characters (8–512).  
- **Settings menu** – toggle modes, adjust word count / length at runtime.  
- **Entropy display** – see the exact entropy (bits) for each generated secret.  
- **Random separators** – between Diceware words a random printable character (not alphanumeric) is inserted.  
- **Memory sanitisation** – all sensitive strings are zeroed before `free()`.  
- **Single‑Enter UX** – after generating a password, press `Enter` once to return to the main menu.

---

## Requirements

- A **C compiler** (GCC, Clang, etc.)
- The **Diceware wordlist** – `diceware.wordlist.asc` in the same directory as the executable.

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

## Compilation

```bash
gcc -o epg epg.c -Wall -Wextra -O2
```

This produces an executable named `epg`. No external libraries are needed.

---

## Usage

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

The current entropy value (bits) is shown next to each setting.

### Generating a password

- In **Diceware mode** – the program outputs a passphrase like:  
  `yaw!lao!defog!upend!bald!nub!trip!whisky`  
  It also shows the number of words, the resulting string length, and the entropy (each word ≈12.9 bits).  
- In **Random mode** – it outputs a fully random password, e.g.:  
  `gT6&kL9$mN2#qR8*XvB5@wP7`  
  with the exact length and entropy (≈6.55 bits per character).

Press **Enter** once to return to the main menu after viewing the password.

---

## Example session

```
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
Enter number of words (4..20): 6

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
Password length: 37 characters
yaw!lao!defog!upend!bald!nub

Press Enter to continue...
```

---

## Security considerations

- The random numbers are generated with `rand()` seeded from `time()` and `getpid()`.  
  *For production / high‑security use, consider replacing the RNG with `getrandom()` or `arc4random()` (the code includes a fallback).*  
- The program zeroes wordlist strings and the temporary passphrase buffer before releasing memory.  
- Diceware mode with **8‑9 words** (≈103‑116 bits) is already resistant to any brute‑force attack, especially if the secret is later fed into a memory‑hard KDF like Argon2id.  
- Random‑character mode at 64 characters gives ≈420 bits of entropy – astronomically secure.

---

## License

MIT License – see the [LICENSE](LICENSE) file (or feel free to reuse the code under the MIT terms).

---

## Acknowledgements

- The Diceware wordlist is created by Arnold Reinhold ([diceware.com](https://diceware.com)).  
- Inspired by the need for a simple, transparent, and entropy‑aware password generator in pure C.
```
