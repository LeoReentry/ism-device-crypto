//
// Created by leo on 11/15/16.
//

#ifndef TPM_GLOBAL_H

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

#define KEY_FILE "%s/%s.k"
#define DATA_FILE "%s/%s.f"
#define PATH "%s/.deh"

#define KEYPATH "/home/leo/Documents/master/key"
//#define FILEPATH "/home/leo/Documents/master/connectionstring"
#define KEY_UUID {0,0,0,0,0,{0,0,0,2,10}}
#define KEY_SIZE 32 // 256 / 8

#define TPM_GLOBAL_H

int fileExists(const char *filename);
/// Closes open handles and exits with failure code.
void ExitFailure(void);
/// Prints depending on verbosity level
/// \param str String to print
void print_info(char* str);
/// Handles errors in error stack for openSSL
void handleErrors(void);

// GLOBAL VARIABLES
const char* HELP_STRING;
int verbose;

#endif //TPM_GLOBAL_H
