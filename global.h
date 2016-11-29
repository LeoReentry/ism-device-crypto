//
// Created by leo on 11/15/16.
//

#ifndef TPM_GLOBAL_H
#define TPM_GLOBAL_H

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <tss/tss_error.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include <sys/stat.h>

// For path handling to key and data files
#define KEY_FILE "%s/%s.k"
#define DATA_FILE "%s/%s.f"
#define PATH "%s/.deh"
// Default name for key when none is given by user
#define DEFAULT_NAME "default"

// UUID to identify TPM key
#define KEY_UUID {0,0,0,0,0,{0,0,0,2,10}}
// Size of AES key in Bytes (256 bits = 32 Byte)
#define KEY_SIZE 32


int fileExists(const char *filename);
/// Closes open handles and exits with failure code.
void ExitFailure(void);
/// Prints depending on verbosity level
/// \param str String to print
void print_info(char* str);
/// Handles errors in error stack for openSSL
void handleErrors(void);

// GLOBAL VARIABLES
// String that displays help regarding the use of the program
const char* HELP_STRING;
// If set to 1, program will print more information
int verbose;

#endif //TPM_GLOBAL_H
