/**@file LicenseGeneration.c
 *  The execution of the license generation process
 */
#include <stdio.h>
#include <stdlib.h>

#include "../Headers/LicenseGenerationController/LicenseMainCaller.h"

int main(int argc, char* argv[]) {
    char isSuccess = 0x0;

	// Calling the start function
	isSuccess = start(argc, argv);

    return (int)isSuccess;
}