/*************************************************************************
	> File Name: debug.h
	> Author: wenkun
	> Mail: wenkun@yunmaoinfo.com
	> Created Time: 2015年01月19日 星期一 17时34分05秒
 ************************************************************************/
#ifndef __DEBUG_H__
#define __DEBUG_H__

extern int g_bDebug;

typedef enum
{
   LOG_LEVEL_ERR    = 1, /**< Message at error level. */
   LOG_LEVEL_NOTICE = 2, /**< Message at notice level. */
   LOG_LEVEL_INFO   = 3, /**< Message at notice level. */
   LOG_LEVEL_DEBUG  = 4  /**< Message at debug level. */
} DebugLevel;

/** @brief Used to output messages.
 *The messages will include the finlname and line number, and will be sent to syslog if so configured in the config file
 */
#define debug(...) _debug(__BASE_FILE__, __LINE__, __VA_ARGS__)

/** @internal */
void _debug(const char filename[], int line, int level, const char *format, ...);

#define DEBUG(level, format, ...) {\
  if(g_bDebug >= level){\
    fprintf(stderr,"(ETWS)[%s@%d]"format"\n", __FILE__, __LINE__, ##__VA_ARGS__);\
  }\
}\

#endif

