#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* Copyright 2021 Melwyn Francis Carlo */


typedef enum
{
    LOWERCASE_LETTER, 
    UPPERCASE_LETTER, 
    NUMERICAL_DIGIT, 
    SPECIAL_CHARACTER 

} CharMode;


typedef enum
{
    false, 
    true 

} bool;


CharMode get_random_charmode()
{
    return (CharMode) (rand() % 4);
}


char get_random_character(CharMode input_charMode)
{
    static const int LOWERCASE_LETTERS_ASCII_LIST [26] = 
    {
         97,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 
        110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122 
    };

    static const int UPPERCASE_LETTERS_ASCII_LIST [26] = 
    {
        65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 
        78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90 
    };

    static const int NUMERICAL_DIGITS_ASCII_LIST [10] = 
    {
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57 
    };

    static const int SPECIAL_CHARACTERS_ASCII_LIST [33] = 
    {
         32,  33,  34,  35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 
         58,  59,  60,  61, 62, 63, 64, 
         91,  92,  93,  94, 95, 96, 
        123, 124, 125, 126 
    };

    char randomCharacter = (char) 0;

    switch (input_charMode)
    {
        case LOWERCASE_LETTER:
            randomCharacter = (char) LOWERCASE_LETTERS_ASCII_LIST [rand() % 26];
            break;

        case UPPERCASE_LETTER:
            randomCharacter = (char) UPPERCASE_LETTERS_ASCII_LIST [rand() % 26];
            break;

        case NUMERICAL_DIGIT:
            randomCharacter = (char) NUMERICAL_DIGITS_ASCII_LIST [rand() % 10];
            break;

        case SPECIAL_CHARACTER:
            randomCharacter = (char) SPECIAL_CHARACTERS_ASCII_LIST [rand() % 33];
            break;
    }

    return randomCharacter;
}

bool validate_string_is_number(const char *input_string, size_t input_string_len, bool is_binary)
{
    for (size_t i = 0; i < input_string_len; i++)
    {
        if ( ! isdigit(input_string [i])) return false;

        if (is_binary)
        {
            if (input_string [i] > '1')  return false;
        }
    }

    return true;
}


char *randpass( const unsigned int maxPassChars, 
                const unsigned int allowedCharSet [4], 
                const unsigned int discardedChars_n, 
                const char *discardedChars)
{
    struct timespec ts;

    timespec_get(&ts, TIME_UTC);

    srand(ts.tv_nsec);

    /* The plus one (+1) is for the null terminator. */
    char *outputPassword = (char *) malloc((maxPassChars + 1) * sizeof(char));

    outputPassword [maxPassChars] = (char) 0;

    for (unsigned int i = 0; i < maxPassChars; i++)
    {
        CharMode randomCharMode = get_random_charmode();

        while ( ! allowedCharSet [(int) randomCharMode]) randomCharMode = get_random_charmode();

        bool invalidChar_found = true;

        while (invalidChar_found)
        {
            /* A hopeful assumption. */
            invalidChar_found = false;

            outputPassword [i] = get_random_character (randomCharMode);

            for (unsigned int j = 0; j < discardedChars_n; j++)
            {
                if (outputPassword [i] == discardedChars [j])
                {
                    invalidChar_found = true;
                    break;
                }
            }
        }
    }

    return outputPassword;
}


int main(int argc, char **argv)
{
    const unsigned int MAXIMUM_INT_LEN = (unsigned int) 1E10;

    if (argc < 2)
    {
        printf("\n Error: Atleast one argument must be provided.\n\n");
        return 0;
    }

    const char *maxPassChars_string = argv [1];

    if ( ! validate_string_is_number(maxPassChars_string, strlen(maxPassChars_string), false))
    {
        printf("\n Error: The first argument (maximum password characters) must be a number.\n\n");
        return 0;
    }

    const unsigned int maxPassChars = (unsigned int) strtoul(maxPassChars_string, NULL, 10);

    if (maxPassChars == 0)
    {
        printf("\n Error: The first argument (maximum password characters) cannot be zero (0).\n\n");
        return 0;
    }

    if (maxPassChars > MAXIMUM_INT_LEN)
    {
        printf("\n Error: The first argument (maximum password characters) cannot be a negative (or a large) number.\n\n");
        return 0;
    }

    /* All character types allowed is the default. */
    char *allowedCharSet_string = "1111";

    if (argc > 2)
    {
        allowedCharSet_string = argv [2];

        if ( strlen(allowedCharSet_string) != 4)
        {
            printf("\n Error: The second argument (allowed characters set) must be a four-digit binary number.\n\n");
            return 0;
        }

        if ( ! validate_string_is_number(allowedCharSet_string, strlen(allowedCharSet_string), true))
        {
            printf("\n Error: The second argument (allowed characters set) must be a four-digit binary number.\n\n");
            return 0;
        }
    }

    const unsigned int allowedCharSet [4] = 
    {
        allowedCharSet_string [0] - '0', 
        allowedCharSet_string [1] - '0', 
        allowedCharSet_string [2] - '0', 
        allowedCharSet_string [3] - '0' 
    };

    char *discardedChars = NULL;

    unsigned int discardedChars_n = 0;

    for (int i = 3; i < argc; i++)
    {
        if (strlen(argv [i]) != 1)
        {
            printf("\n Error: From the third argument (discarded characters) onwards, only characters are accepted.\n\n");
            return 0;
        }

        bool duplicateChar_found = false;

        for (unsigned int j = 0; j < discardedChars_n; j++)
        {
            if (argv [i] [0] == discardedChars [j])
            {
                duplicateChar_found = true;
                break;
            }
        }

        if (duplicateChar_found) continue;

        discardedChars_n++;

        if (discardedChars == NULL)
        {
            discardedChars = (char *) malloc(sizeof(char));
        }
        else
        {
            discardedChars = (char *) realloc(discardedChars, discardedChars_n * sizeof(char));
        }

        discardedChars [discardedChars_n - 1] = argv [i] [0];
    }

    char *generatedPassword = randpass( maxPassChars, 
                                        allowedCharSet, 
                                        discardedChars_n, 
                                        discardedChars);

    printf("\n Result: %s\n\n", generatedPassword);

    free(generatedPassword);

    generatedPassword = NULL;

    return 0;
}

