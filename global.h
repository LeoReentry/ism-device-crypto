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

#define KEYPATH "/home/leo/Documents/master/key"
#define FILEPATH "/home/leo/Documents/master/connectionstring"
#define KEY_UUID {0,0,0,0,0,{0,0,0,2,10}}
#define KEY_SIZE 32 // 256 / 8

#define TPM_GLOBAL_H

/// \brief Initializes handles that are necessary for all TPM operations.
///
/// Initializes handles for Context and SRK, gets their policies and sets their policy secrets to the well-known secrets.
/// \return integer
/// \retval 0 for success
/// \retval 1 for failure
int TPM_InitContext(void);
/// \brief Closes the handles opened before.
/// \return void
void TPM_CloseContext(void);
/// \brief Checks if a file exists
/// @param filename String with the complete path to the file
/// \returns integer
/// \retval 1 for true
/// \retval 0 for false
int fileExists(const char *filename);
/// Closes open handles and exits with failure code.
void ExitFailure(void);
/// Prints depending on verbosity level
/// \param str String to print
void print_info(char* str);

// GLOBAL VARIABLES
int verbose;
TSS_HCONTEXT hContext;
TSS_HTPM hTPM;
TSS_HPOLICY hTPMPolicy;
TSS_RESULT result;
TSS_HKEY hSRK;
TSS_HPOLICY hSRKPolicy;
TSS_UUID SRK_UUID;
BYTE wks[20]; //For the well known secret

#endif //TPM_GLOBAL_H
