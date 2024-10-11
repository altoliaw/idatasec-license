#pragma once
/** @file Time.h
 * The timestamp class
 *
 * @author Nick, Liao
 * @date 2024/10/09
 *
 * @note The time zone information, generated from ChatGPT <br />
 * | Time Zone Name | Abbreviation | TZ String | Description |
 * | Coordinated Universal Time | UTC | UTC | Coordinated Universal Time |
 * | Greenwich Mean Time | GMT | GMT | Greenwich Mean Time |
 * | Eastern Standard Time | EST | EST5EDT | North American Eastern Standard Time |
 * | Central Standard Time | CST | CST6CDT | North American Central Standard Time |
 * | Mountain Standard Time | MST | MST7MDT | North American Mountain Standard Time |
 * | Pacific Standard Time | PST | PST8PDT | North American Pacific Standard Time |
 * | Alaska Standard Time | AKST | AKST9AKDT | Alaska Standard Time |
 * | Hawaii-Aleutian Standard Time | HAST | HAST10HADT | Hawaii-Aleutian Standard Time |
 * | Japan Standard Time | JST | JST-9 | Japan Standard Time |
 * | China Standard Time | CST | CST-8 | China Standard Time |
 * | India Standard Time | IST | IST-5:30 | India Standard Time |
 * | Australian Eastern Standard Time | AEST | AEST-10AEDT | Australian Eastern Standard Time |
 * | Australian Central Standard Time | ACST | ACST-9:30ACDT | Australian Central Standard Time |
 * | Australian Western Standard Time | AWST | AWST-8 | Australian Western Standard Time |
 * | Central European Time | CET | CET-1CEST | Central European Time |
 * | Eastern European Time | EET | EET-2EEST | Eastern European Time |
 * | Newfoundland Standard Time | NST | NST3:30NDT | Newfoundland Standard Time |
 */
#ifndef __USE_XOPEN  // For strptime(.) in time.h
#define __USE_XOPEN
#endif

#ifndef _GNU_SOURCE  // For strptime(.) in time.h
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct Time Time;
typedef enum TimeZone Timezone;

/**
 * Time zone definition
 */
enum TimeZone{
    UTC = 0,  // Coordinated Universal Time
    GMT,      // Greenwich Mean Time
    PST,      // North American Pacific Standard Time
    NST       // Newfoundland Standard Time
};

struct Time {
    // Providing a pointer for referring the static value in this class; a static pointer declaration
    long* timeEpochPointer;

    // Obtaining the epoch with the current time (using 0 as an argument) or the specified time epoch;
    // please refer to the "getEpoch" function (@see getEpoch)
    long (*getEpoch)(Time*, time_t);
    // Obtaining the specified epoch time; please refer to the function, getStringToEpoch
    // (@see getStringToEpoch)
    long (*getStringToEpoch)(Time*, const char*);
    // For releasing the static variable from the methods in the class (@see releaseInitializedFileParserInitialization)
    void (*releaseInitializedFileParserInitialization)(Time*);
    // For transforming the linux utc to the string with users' specified format (@see getEpochToString)
    void (*getEpochToString)(Time*, const char*, Timezone, long, unsigned char**);
};

// Time constructor
void Time_Constrcut(Time*);
// Time destructor
void Time_Destrcut(Time*);