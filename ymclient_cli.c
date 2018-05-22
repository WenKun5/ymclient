/*************************************************************************
    > File Name: meshguard.c
    > Author: wenkun
    > Mail: wenkun@etonetech.com
    > Created Time: Fri 09 May 2018 04:14:46 PM CST
 ************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>


/* for strerror() */
#include <string.h>

#include "conf.h"
#include "ymclient.h"
#include "debug.h"
#include "commandline.h"

#define MINIMUM_STARTED_TIME 1178487900 /* 2007-05-06 */
/* Time when nodogsplash started  */
time_t started_time = 0;

int test(void)
{
    int ret = 0;
    ETC_REG_RESPONSE_S regData;

    memset(&regData, 0, sizeof(regData));

    ret = etc_heartbeat_request(&regData);
    if (ret == ETC_OK)
    {
        printf("REG: download:%d, upload:%d]\n", regData.downloadLimit, regData.uploadLimit);
    }

    return 0;
}

#if 1

/** @internal
 * Registers all the signal handlers
 */
static void init_signals(void)
{
    struct sigaction sa;
#if 0
    debug(LOG_DEBUG, "Setting SIGCHLD handler to sigchld_handler()");
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }
#endif
    /* Trap SIGPIPE */
    /* This is done so that when libhttpd does a socket operation on
     * a disconnected socket (i.e.: Broken Pipes) we catch the signal
     * and do nothing. The alternative is to exit. SIGPIPE are harmless
     * if not desirable.
     */
    debug(LOG_DEBUG, "Setting SIGPIPE  handler to SIG_IGN");
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }
#if 0
    debug(LOG_DEBUG, "Setting SIGTERM,SIGQUIT,SIGINT  handlers to termination_handler()");
    sa.sa_handler = termination_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
#endif
    /* Trap SIGTERM */
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGQUIT */
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGINT */
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }
}

static void main_loop(void)
{
    int ret = 0;

#if 0
    pthread_t tid;
#endif
    s_config *config;

    // TODO: Do initial
    /* 1. Load config from config file */
    config = config_get_config();

    /* Set the time when nodogsplash started */
    if (!started_time) {
        debug(LOG_INFO, "Setting started_time");
        started_time = time(NULL);
    } else if (started_time < MINIMUM_STARTED_TIME) {
        debug(LOG_WARNING, "Detected possible clock skew - re-setting started_time");
        started_time = time(NULL);
    }

#if 0
    ret = pthread_create(&tid_hearbeat, NULL, thread_process_heartbeat, NULL);
    if (ret != 0)
    {
        debug(LOG_ERR, "FATAL: Failed to create thread_process_heartbeat -exit");
        termination_handler(0);
    }
    ret = pthread_join(tid, NULL);
    if (ret)
    {
        debug(LOG_INFO, "Failed")
    }
#endif

}

#endif


int main(int argc, char **argv)
{
    int ret = 0;
    s_config *config;

    /* 1. Load config from config file */
    config = config_get_config();
    config_init();

    parse_commandline(argc, argv);

    /* Initialize the config */
    debug(LOG_NOTICE,"Reading and validating configuration file %s", config->configfile);
    config_read(config->configfile);
    config_validate();

    /* 2. Global init */
    init_signals();

    /* 3. */
    if (config->daemon)
    {
        switch(safe_fork()){
        case 0:
            setsid();
            main_loop();
            break;
        default:
            exit(0);
            break;
        }
    }else{
        main_loop();
    }

    return(0);
}
