/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/** @file conf.h
    @brief Config file parsing
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
    @author Copyright (C) 2007 Paul Kube <nodogsplash@kokoro.ucsd.edu>
    @author Copyright (C) 2018 WenKun <wenkun@etonetech.com>
*/

#ifndef _CONF_H_
#define _CONF_H_

#define VERSION "2.0.0-git"

/*@{*/
/** Defines */
/** How many times should we try detecting the interface with the default route
 * (in seconds).  If set to 0, it will keep retrying forever */
#define NUM_EXT_INTERFACE_DETECT_RETRY 0
/** How long we should wait per try
 *  to detect the interface with the default route if it isn't up yet (interval in seconds) */
#define EXT_INTERFACE_DETECT_RETRY_INTERVAL 1
#define MAC_ALLOW 0 /** macmechanism to block MAC's unless allowed */
#define MAC_BLOCK 1 /** macmechanism to allow MAC's unless blocked */

/** Defaults configuration values */
#ifndef SYSCONFDIR
#define DEFAULT_CONFIGFILE "./ymclient.conf"
#else
#define DEFAULT_CONFIGFILE SYSCONFDIR"/nodogsplash/nodogsplash.conf"
#endif
#define DEFAULT_DAEMON 1
#define DEFAULT_DEBUGLEVEL LOG_WARNING
#define DEFAULT_MAXCLIENTS 20
#define DEFAULT_GATEWAY_IPRANGE "0.0.0.0/0"
#define DEFAULT_GATEWAYNAME "NoDogSplash"
#define DEFAULT_GATEWAYPORT 2050
#define DEFAULT_REMOTE_AUTH_PORT 80
#define DEFAULT_CHECKINTERVAL 60
#define DEFAULT_CLIENTTIMEOUT 10
#define DEFAULT_CLIENTFORCEOUT 360
#define DEFAULT_MACMECHANISM MAC_BLOCK
#define DEFAULT_TRAFFIC_CONTROL 0
#define DEFAULT_UPLOAD_LIMIT 0
#define DEFAULT_DOWNLOAD_LIMIT 0
#define DEFAULT_LOG_SYSLOG 0
#define DEFAULT_SYSLOG_FACILITY LOG_DAEMON
#define DEFAULT_NDSCTL_SOCK "/tmp/ndsctl.sock"
#define DEFAULT_INTERNAL_SOCK "/tmp/ndsctl.sock"

#define DEFAULT_DISTANCE 10000
#define DEFAULT_TXPOWER  13
#define DEFAULT_NODE_ID  2
#define DEFAULT_SSID   "ETWS"
#define DEFAULT_DEVTYPE ETWS_DEV_TERMINAL
#define DEFAULT_HEARTBEAT_INTERVAL  5
/*@}*/

/**
* Firewall targets
*/
typedef enum {
	TARGET_DROP,
	TARGET_REJECT,
	TARGET_ACCEPT,
	TARGET_LOG,
	TARGET_ULOG
} t_firewall_target;

/**
 * Firewall rules
 */
typedef struct _firewall_rule_t {
	t_firewall_target target;	/**< @brief t_firewall_target */
	char *protocol;		/**< @brief tcp, udp, etc ... */
	char *port;			/**< @brief Port to block/allow */
	char *mask;			/**< @brief Mask for the rule *destination* */
	char *ipset;			/**< @brief IPset rule */
	struct _firewall_rule_t *next;
} t_firewall_rule;

/**
 * Firewall rulesets
 */
typedef struct _firewall_ruleset_t {
	char *name;
	char *emptyrulesetpolicy;
	t_firewall_rule *rules;
	struct _firewall_ruleset_t *next;
} t_firewall_ruleset;

/**
 * MAC Addresses
 */
typedef struct _MAC_t {
	char *mac;
	struct _MAC_t *next;
} t_MAC;

/**
 * Device type
 */
typedef enum {
	ETWS_DEV_TERMINAL,
	ETWS_DEV_STATION,
	ETWS_DEV_PAD
}t_device_type;

/**
 * Configuration structure
 */
typedef struct {
	char configfile[255];	/**< @brief name of the config file */
	char ssid[128];         /**< @brief name of wifi */
	char *ndsctl_sock;		/**< @brief ndsctl path to socket */
	char *internal_sock;	/**< @brief internal path to socket */
	int daemon;			    /**< @brief if daemon > 0, use daemon mode */
	int debuglevel;			/**< @brief Debug information verbosity */
	int maxclients;			/**< @brief Maximum number of clients allowed */
	char *gw_name;			/**< @brief Name of the gateway; e.g. its SSID */
	char *gw_interface;		/**< @brief Interface we will manage */
	char *gw_iprange;		/**< @brief IP range on gw_interface we will manage */
	char *gw_address;		/**< @brief Internal IP address for our web server */
	char *gw_mac;			/**< @brief MAC address of the interface we manage */
	unsigned int gw_port;	/**< @brief Port the webserver will run on */
	unsigned int txpower;   /**< @brief Txpower, dBm */
	t_device_type devType;  /**< @brief Device type, t_device_type */
	int nodeId;             /**< @brief nodeId, Mesh node ID, reference with ipaddr */
	int distance;           /**< @brief Distance for wifi settings */
	int heartbeat;		    /**< @brief Interval seconds of heartbeat */
	int traffic_control;	/**< @brief boolean, whether to do tc */
	int download_limit;		/**< @brief Download limit, kb/s */
	int upload_limit;		/**< @brief Upload limit, kb/s */
	int log_syslog;			/**< @brief boolean, whether to log to syslog */
	int syslog_facility;	/**< @brief facility to use when using syslog for logging */
	int macmechanism; 		/**< @brief mechanism wrt MAC addrs */
	t_firewall_ruleset *rulesets;	/**< @brief firewall rules */
	t_MAC *trustedmaclist;		/**< @brief list of trusted macs */
	t_MAC *blockedmaclist;		/**< @brief list of blocked macs */
	t_MAC *allowedmaclist;		/**< @brief list of allowed macs */
} s_config;

/** @brief Get the current gateway configuration */
s_config *config_get_config(void);

/** @brief Initialise the conf system */
void config_init(void);

/** @brief Initialize the variables we override with the command line*/
void config_init_override(void);

/** @brief Reads the configuration file */
void config_read(const char filename[]);

/** @brief Check that the configuration is valid */
void config_validate(void);

/** @brief Fetch a firewall rule list, given name of the ruleset. */
t_firewall_rule *get_ruleset_list(const char[]);

/** @brief Fetch a firewall ruleset, given its name. */
t_firewall_ruleset *get_ruleset(const char[]);

/** @brief Add a firewall ruleset with the given name, and return it. */
t_firewall_ruleset *add_ruleset(const char[]);

/** @brief Say if a named firewall ruleset is empty. */
int is_empty_ruleset(const char[]);

/** @brief Get a named empty firewall ruleset policy, given ruleset name. */
char * get_empty_ruleset_policy(const char[]);

void parse_trusted_mac_list(const char[]);
void parse_blocked_mac_list(const char[]);
void parse_allowed_mac_list(const char[]);

int add_to_blocked_mac_list(const char possiblemac[]);
int remove_from_blocked_mac_list(const char possiblemac[]);

int add_to_allowed_mac_list(const char possiblemac[]);
int remove_from_allowed_mac_list(const char possiblemac[]);

int remove_from_trusted_mac_list(const char possiblemac[]);
int add_to_trusted_mac_list(const char possiblemac[]);

int check_ip_format(const char[]);
int check_mac_format(const char[]);

/** config API, used in commandline.c */
int set_log_level(int);
int set_password(const char[]);
int set_username(const char[]);

#define LOCK_CONFIG() do { \
	debug(LOG_DEBUG, "Locking config"); \
	pthread_mutex_lock(&config_mutex); \
	debug(LOG_DEBUG, "Config locked"); \
} while (0)

#define UNLOCK_CONFIG() do { \
	debug(LOG_DEBUG, "Unlocking config"); \
	pthread_mutex_unlock(&config_mutex); \
	debug(LOG_DEBUG, "Config unlocked"); \
} while (0)

#endif /* _CONF_H_ */
