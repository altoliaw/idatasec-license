#pragma once
/** @file TimePrototype.hpp
 * The timestamp prototype for later polymorphisms
 *
 * @author William, Chiu; Nick modified
 * @date 2024/06/06
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

#include <string.h>
#include <time.h>

#include <iostream>
#include <memory>
#include <string>

#include "./POSIXErrors.hpp"

#ifdef _WIN32

#include <ctime>
#include <iomanip>
#include <sstream>

#endif

namespace Commons {
/**
 * The time class
 */
class Time {
   public:
    /**
     * Time zone definition
     */
    enum TimeZone {
        UTC = 0,  // Coordinated Universal Time
        GMT,      // Greenwich Mean Time
        PST,      // North American Pacific Standard Time
        NST,      // Newfoundland Standard Time
    };

    // Providing a pointer for referring the static value in this class; a static pointer declaration
    static long* timeEpochPointer;

    static void getTimeInitialization();
    static long getEpoch(time_t = time(NULL));
    static long getStringToEpoch(const char*);
    static std::string getEpochToString(const char*, Time::TimeZone, long = *(Time::timeEpochPointer));
    static Commons::POSIXErrors windowStrptime(const char*, const char*, tm&);

   private:
    Time();
};
}  // namespace Commons