/*
 * epg.c - Entropy Password Generator (Diceware + Random)
 * Compile: gcc -o epg epg.c -Wall -Wextra -O2 -lm
 * Requires: diceware.wordlist.asc in the same directory.
 *
 * Security features:
 * - Cryptographically secure RNG (/dev/urandom)
 * - Rejection sampling eliminates modulo bias for any range
 * - Dynamic entropy based on actual wordlist size
 * - No unsafe atoi(), all input validated with strtol
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <errno.h>
#include <limits.h>

/* --- Constants -------------------------------------------------- */
#define WORDLIST_FILE "diceware.wordlist.asc"
#define MAX_WORDS     8192
#define MAX_PASSPHRASE_LEN 4096
#define ENTROPY_PER_CHAR 6.554    /* log2(94) */

#define DEFAULT_WORD_COUNT 8
#define MIN_WORD_COUNT     4
#define MAX_WORD_COUNT     20

#define DEFAULT_LEN        64
#define MIN_LEN            8
#define MAX_LEN            512

const char SEPARATOR_SET[] = "!@#$%^&*()-_=+[]{}|;:,.<>?/~";
#define SEP_SET_SIZE (sizeof(SEPARATOR_SET)-1)

/* --- Global variables ------------------------------------------- */
char **wordlist = NULL;
int word_count = 0;
int diceware_mode = 1;
int diceware_words = DEFAULT_WORD_COUNT;
int random_len = DEFAULT_LEN;
int urandom_fd = -1;

/* --- CSPRNG Initialisation -------------------------------------- */
static void init_rng(void) {
    urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (urandom_fd < 0) {
        perror("Fatal: Cannot open /dev/urandom");
        exit(1);
    }
}

/* --- Read one secure random byte -------------------------------- */
static int get_secure_random_byte(void) {
    unsigned char byte;
    if (read(urandom_fd, &byte, 1) != 1) {
        perror("Fatal: Failed reading from /dev/urandom");
        exit(1);
    }
    return byte;
}

/* --- Read a 32‑bit secure random value (0 .. 2^32‑1) ------------ */
static unsigned int get_secure_random_32(void) {
    unsigned int r = 0;
    for (int i = 0; i < 4; i++) {
        r = (r << 8) | get_secure_random_byte();
    }
    return r;
}

/* --- Unbiased random index in [0, max-1] (works for any max ≤ 2^31‑1) */
static int unbiased_index(int max) {
    if (max <= 0) return 0;
    /* Use 32‑bit random values, reject values that would cause bias */
    unsigned int limit = 0xFFFFFFFFU - (0xFFFFFFFFU % (unsigned int)max);
    unsigned int r;
    do {
        r = get_secure_random_32();
    } while (r >= limit);
    return (int)(r % (unsigned int)max);
}

/* --- Random printable ASCII (33‑126) ---------------------------- */
static char random_printable(void) {
    return (char)(33 + unbiased_index(94));
}

/* --- Random character from a given set -------------------------- */
static char random_char_from_set(const char *set, int set_size) {
    return set[unbiased_index(set_size)];
}

/* --- Secure memory zero (glibc has explicit_bzero, else fallback) */
static void secure_zero(void *ptr, size_t len) {
#ifdef __GLIBC__
    explicit_bzero(ptr, len);
#else
    volatile char *p = (volatile char *)ptr;
    while (len--) *p++ = 0;
#endif
}

/* --- Flush stdin (single Enter wait) ---------------------------- */
static void flush_stdin(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

/* --- Load Diceware wordlist (robust parsing) -------------------- */
static int load_wordlist(void) {
    FILE *f = fopen(WORDLIST_FILE, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open '%s'\n", WORDLIST_FILE);
        return 0;
    }

    wordlist = malloc(MAX_WORDS * sizeof(char *));
    if (!wordlist) { fclose(f); return 0; }

    word_count = 0;
    char line[512];
    while (fgets(line, sizeof(line), f) && word_count < MAX_WORDS) {
        /* Remove trailing newline/carriage return */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        if (line[0] == '/' || line[0] == '#') continue;
        if (!isdigit((unsigned char)line[0])) continue;

        char *p = line;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (!*p) continue;
        *p = '\0';
        p++;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) continue;

        wordlist[word_count] = strdup(p);
        if (!wordlist[word_count]) break;
        word_count++;
    }
    fclose(f);

    if (word_count == 0) {
        fprintf(stderr, "Error: No words loaded. Check file format.\n");
        free(wordlist);
        wordlist = NULL;
        return 0;
    }
    printf("Loaded %d Diceware words.\n", word_count);
    return 1;
}

static void free_wordlist(void) {
    if (wordlist) {
        for (int i = 0; i < word_count; i++) {
            if (wordlist[i]) {
                secure_zero(wordlist[i], strlen(wordlist[i]));
                free(wordlist[i]);
            }
        }
        free(wordlist);
        wordlist = NULL;
    }
    word_count = 0;
}

/* --- Diceware passphrase (exact number of words) ---------------- */
static void generate_diceware_passphrase(char *out, int out_size, int nwords) {
    if (word_count == 0) {
        snprintf(out, out_size, "ERROR: No wordlist");
        return;
    }
    if (nwords < 1) nwords = 1;
    if (nwords > MAX_WORD_COUNT) nwords = MAX_WORD_COUNT;

    char buffer[MAX_PASSPHRASE_LEN] = {0};
    size_t pos = 0;

    for (int i = 0; i < nwords; i++) {
        int idx = unbiased_index(word_count);
        const char *word = wordlist[idx];
        size_t word_len = strlen(word);
        if (pos + word_len + 2 >= sizeof(buffer)) break;
        memcpy(buffer + pos, word, word_len);
        pos += word_len;
        if (i < nwords - 1) {
            char sep = random_char_from_set(SEPARATOR_SET, SEP_SET_SIZE);
            buffer[pos++] = sep;
        }
    }
    buffer[pos] = '\0';
    strncpy(out, buffer, out_size - 1);
    out[out_size - 1] = '\0';
    secure_zero(buffer, sizeof(buffer));
}

/* --- Random character password ---------------------------------- */
static void generate_random_password(char *out, int length) {
    for (int i = 0; i < length; i++)
        out[i] = random_printable();
    out[length] = '\0';
}

/* --- Safe integer input ----------------------------------------- */
static int get_int_input(int min, int max, const char *prompt) {
    char buf[32];
    long val;
    char *endptr;
    while (1) {
        printf("%s", prompt);
        if (!fgets(buf, sizeof(buf), stdin)) return min;
        errno = 0;
        val = strtol(buf, &endptr, 10);
        if (errno != 0 || endptr == buf || *endptr != '\n' || val < min || val > max) {
            printf("Invalid input. Please enter a number between %d and %d.\n", min, max);
        } else {
            return (int)val;
        }
    }
}

/* --- Menu: Generate password ------------------------------------ */
static void menu_generate(void) {
    if (diceware_mode && word_count == 0) {
        printf("\nERROR: Diceware mode selected but no wordlist loaded.\n");
        printf("Press Enter to continue...");
        flush_stdin();
        return;
    }

    char password[MAX_PASSPHRASE_LEN + 10] = {0};
    double actual_entropy;
    int actual_len = 0;

    if (diceware_mode) {
        generate_diceware_passphrase(password, sizeof(password), diceware_words);
        actual_entropy = diceware_words * log2(word_count);
        actual_len = strlen(password);
        printf("\n--- Diceware Passphrase (%d words, entropy ≈ %.1f bits) ---\n",
               diceware_words, actual_entropy);
        printf("Password length: %d characters\n", actual_len);
        printf("%s\n", password);
    } else {
        generate_random_password(password, random_len);
        actual_entropy = random_len * ENTROPY_PER_CHAR;
        printf("\n--- Random Password (%d chars, entropy ≈ %.1f bits) ---\n",
               random_len, actual_entropy);
        printf("%s\n", password);
    }
    printf("\nPress Enter to continue...");
    flush_stdin();
}

/* --- Menu: Settings --------------------------------------------- */
static void menu_settings(void) {
    int choice;
    do {
        printf("\n=== Password Settings ===\n");
        printf("1. Toggle mode: %s\n", diceware_mode ? "Diceware (words)" : "Random characters");
        if (diceware_mode) {
            printf("2. Set number of words (current: %d) [entropy: %.1f bits]\n",
                   diceware_words, diceware_words * log2(word_count));
        } else {
            printf("2. Set password length (current: %d) [entropy: %.1f bits]\n",
                   random_len, random_len * ENTROPY_PER_CHAR);
        }
        printf("3. Return to main menu\n");
        printf("Choice: ");
        char buf[32];
        if (!fgets(buf, sizeof(buf), stdin)) break;
        choice = (int)strtol(buf, NULL, 10);
        switch (choice) {
            case 1:
                diceware_mode = !diceware_mode;
                printf("Mode changed to %s.\n", diceware_mode ? "Diceware" : "Random characters");
                break;
            case 2:
                if (diceware_mode) {
                    int new_words = get_int_input(MIN_WORD_COUNT, MAX_WORD_COUNT,
                                                  "Enter number of words: ");
                    diceware_words = new_words;
                    printf("Will use %d words (≈ %.1f bits entropy).\n",
                           diceware_words, diceware_words * log2(word_count));
                } else {
                    int new_len = get_int_input(MIN_LEN, MAX_LEN,
                                                "Enter password length: ");
                    random_len = new_len;
                    printf("Password length set to %d (≈ %.1f bits entropy).\n",
                           random_len, random_len * ENTROPY_PER_CHAR);
                }
                break;
            case 3:
                return;
            default:
                printf("Invalid choice.\n");
        }
    } while (1);
}

/* --- Main ------------------------------------------------------- */
int main(void) {
    init_rng();
    if (!load_wordlist()) {
        fprintf(stderr, "Exiting.\n");
        close(urandom_fd);
        return 1;
    }

    int choice;
    do {
        printf("\n=== Entropy Password Generator ===\n");
        printf("1. Generate password\n");
        printf("2. Settings\n");
        printf("3. Exit (sanitize memory)\n");
        printf("Choice: ");
        char buf[16];
        if (!fgets(buf, sizeof(buf), stdin)) break;
        choice = (int)strtol(buf, NULL, 10);
        switch (choice) {
            case 1:
                menu_generate();
                break;
            case 2:
                menu_settings();
                break;
            case 3:
                printf("Exiting and sanitizing memory...\n");
                free_wordlist();
                close(urandom_fd);
                return 0;
            default:
                printf("Invalid choice.\n");
        }
    } while (1);

    free_wordlist();
    close(urandom_fd);
    return 0;
}
