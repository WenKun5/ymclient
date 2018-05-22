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

/** @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Paul Kube <nodogsplash@kokoro.ucsd.edu>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

//#include <pthread.h>

#include <string.h>
#include <ctype.h>

//#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"

//#include "util.h"

#define MAX_BUF 4096

/** @internal
 * Holds the current configuration of the gateway */
static s_config config;

#if 0
/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/** @internal
 * A flag.  If set to 1, there are missing or empty mandatory parameters in the config
 */
static int missing_parms;

/** @internal
 The different configuration options */
typedef enum {
	oBadOption,
	oDaemon,
	oDebugLevel,
	oMaxClients,
	oGatewayName,
	oGatewayInterface,
	oGatewayIPRange,
	oGatewayAddress,
	oGatewayPort,
	oTrafficControl,
	oDownloadLimit,
	oUploadLimit,
	oSyslogFacility,
	oMACmechanism,
	oTrustedMACList,
	oBlockedMACList,
	oAllowedMACList,
	oTxpower,
	oDevType,
	oNodeId,
	oDistance,
	oHeartBeat,

} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
	const char *name;
	OpCodes opcode;
	int required;
} keywords[] = {
	{ "daemon", oDaemon },
	{ "debuglevel", oDebugLevel },
	{ "maxclients", oMaxClients },
	{ "gatewayname", oGatewayName },
	{ "gatewayinterface", oGatewayInterface },
	{ "gatewayiprange", oGatewayIPRange },
	{ "gatewayaddress", oGatewayAddress },
	{ "gatewayport", oGatewayPort },
	{ "trafficcontrol",	oTrafficControl },
	{ "downloadlimit", oDownloadLimit },
	{ "uploadlimit", oUploadLimit },
	{ "trustedmaclist", oTrustedMACList },
	{ "blockedmaclist", oBlockedMACList },
	{ "allowedmaclist", oAllowedMACList },
	{ "MACmechanism", oMACmechanism },
	{ "txpower", oTxpower },
	{ "devType", oDevType },
	{ "distance", oDistance},
	{ "heartbeat", oHeartBeat},
	{ "nodeId", oNodeId},
	{ NULL, oBadOption },
};

static void config_notnull(const void *parm, const char *parmname);
static int parse_boolean_value(char *);
static int _parse_firewall_rule(t_firewall_ruleset *ruleset, char *leftover);
static void parse_firewall_ruleset(const char *, FILE *, const char *, int *);

static OpCodes config_parse_opcode(const char *cp, const char *filename, int linenum);

/** @internal
Strip comments and leading and trailing whitespace from a string.
Return a pointer to the first nonspace char in the string.
*/
static char* _strip_whitespace(char* p1);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
s_config *
config_get_config(void)
{
	return &config;
}

/** Sets the default config parameters and initialises the configuration system */
void
config_init(void)
{
	t_firewall_ruleset *rs;

	debug(LOG_DEBUG, "Setting default config parameters");
	strncpy(config.configfile, DEFAULT_CONFIGFILE, sizeof(config.configfile));
	strcpy(config.ssid, DEFAULT_SSID);
	config.debuglevel = DEFAULT_DEBUGLEVEL;
	config.maxclients = DEFAULT_MAXCLIENTS;
	config.gw_name = safe_strdup(DEFAULT_GATEWAYNAME);
	config.gw_interface = NULL;
	config.gw_iprange = safe_strdup(DEFAULT_GATEWAY_IPRANGE);
	config.gw_address = NULL;
	config.gw_port = DEFAULT_GATEWAYPORT;
	config.daemon = -1;
	config.txpower = DEFAULT_TXPOWER;
	config.devType = DEFAULT_DEVTYPE;
	config.nodeId = DEFAULT_NODE_ID;
	config.distance = DEFAULT_DISTANCE;
	config.heartbeat = DEFAULT_HEARTBEAT_INTERVAL;
	config.traffic_control = DEFAULT_TRAFFIC_CONTROL;
	config.upload_limit =  DEFAULT_UPLOAD_LIMIT;
	config.download_limit = DEFAULT_DOWNLOAD_LIMIT;
	config.syslog_facility = DEFAULT_SYSLOG_FACILITY;
	config.log_syslog = DEFAULT_LOG_SYSLOG;
	config.trustedmaclist = NULL;
	config.blockedmaclist = NULL;
	config.allowedmaclist = NULL;
	config.macmechanism = DEFAULT_MACMECHANISM;
}

/**
 * If the command-line didn't specify a config, use the default.
 */
void
config_init_override(void)
{
	if (config.daemon == -1) config.daemon = DEFAULT_DAEMON;
}

/** @internal
Attempts to parse an opcode from the config file
*/
static OpCodes
config_parse_opcode(const char *cp, const char *filename, int linenum)
{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;

	debug(LOG_ERR, "%s: line %d: Bad configuration option: %s", filename, linenum, cp);
	return oBadOption;
}

/**
Advance to the next word
@param s string to parse, this is the next_word pointer, the value of s
	 when the macro is called is the current word, after the macro
	 completes, s contains the beginning of the NEXT word, so you
	 need to save s to something else before doing TO_NEXT_WORD
@param e should be 0 when calling TO_NEXT_WORD(), it'll be changed to 1
	 if the end of the string is reached.
*/
#define TO_NEXT_WORD(s, e) do { \
	while (*s != '\0' && !isblank(*s)) { \
		s++; \
	} \
	if (*s != '\0') { \
		*s = '\0'; \
		s++; \
		while (isblank(*s)) \
			s++; \
	} else { \
		e = 1; \
	} \
} while (0)

/** @internal
Strip comments and leading and trailing whitespace from a string.
Return a pointer to the first nonspace char in the string.
*/
static char*
_strip_whitespace(char* p1)
{
	char *p2, *p3;

	p3 = p1;
	while ((p2 = strchr(p3,'#')) != 0) {  /* strip the comment */
		/* but allow # to be escaped by \ */
		if (p2 > p1 && (*(p2 - 1) == '\\')) {
			p3 = p2 + 1;
			continue;
		}
		*p2 = '\0';
		break;
	}

	/* strip leading whitespace */
	while(isspace(p1[0])) p1++;
	/* strip trailing whitespace */
	while(p1[0] != '\0' && isspace(p1[strlen(p1)-1]))
		p1[strlen(p1)-1] = '\0';

	return p1;
}

/**
@param filename Full path of the configuration file to be read
*/
void
config_read(const char *filename)
{
	FILE *fd;
	char line[MAX_BUF], *s, *p1, *p2;
	int linenum = 0, opcode, value;

	debug(LOG_INFO, "Reading configuration file '%s'", filename);

	if (!(fd = fopen(filename, "r"))) {
		debug(LOG_ERR, "FATAL: Could not open configuration file '%s', "
			  "exiting...", filename);
		exit(1);
	}

	while (fgets(line, MAX_BUF, fd)) {
		linenum++;
		s = _strip_whitespace(line);

		/* if nothing left, get next line */
		if (s[0] == '\0') continue;

		/* now we require the line must have form: <option><whitespace><arg>
		 * even if <arg> is just a left brace, for example
		 */

		/* find first word (i.e. option) end boundary */
		p1 = s;
		while ((*p1 != '\0') && (!isspace(*p1))) p1++;
		/* if this is end of line, it's a problem */
		if (p1[0] == '\0') {
			debug(LOG_ERR, "Option %s requires argument on line %d in %s", s, linenum, filename);
			debug(LOG_ERR, "Exiting...");
			exit(-1);
		}

		/* terminate option, point past it */
		*p1 = '\0';
		p1++;

		/* skip any additional leading whitespace, make p1 point at start of arg */
		while (isblank(*p1)) p1++;

		debug(LOG_DEBUG, "Parsing option: %s, arg: %s", s, p1);
		opcode = config_parse_opcode(s, filename, linenum);

		switch(opcode) {
		case oDaemon:
			if (config.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
				config.daemon = value;
			}
			break;
		case oDebugLevel:
			if (sscanf(p1, "%d", &config.debuglevel) < 1 || config.debuglevel < LOG_EMERG || config.debuglevel > LOG_DEBUG) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s. Valid debuglevel %d..%d", p1, s, linenum, filename, LOG_EMERG, LOG_DEBUG);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oMaxClients:
			if (sscanf(p1, "%d", &config.maxclients) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oGatewayName:
			config.gw_name = safe_strdup(p1);
			break;
		case oGatewayInterface:
			config.gw_interface = safe_strdup(p1);
			break;
		case oGatewayIPRange:
			config.gw_iprange = safe_strdup(p1);
			break;
		case oGatewayAddress:
			config.gw_address = safe_strdup(p1);
			break;
		case oGatewayPort:
			if (sscanf(p1, "%u", &config.gw_port) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oTrustedMACList:
			parse_trusted_mac_list(p1);
			break;
		case oBlockedMACList:
			parse_blocked_mac_list(p1);
			break;
		case oAllowedMACList:
			parse_allowed_mac_list(p1);
			break;
		case oMACmechanism:
			if (!strcasecmp("allow",p1)) config.macmechanism = MAC_ALLOW;
			else if (!strcasecmp("block",p1)) config.macmechanism = MAC_BLOCK;
			else {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oTrafficControl:
			if ((value = parse_boolean_value(p1)) != -1) {
				config.traffic_control = value;
			} else {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oDownloadLimit:
			if (sscanf(p1, "%d", &config.download_limit) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oUploadLimit:
			if (sscanf(p1, "%d", &config.upload_limit) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oSyslogFacility:
			if (sscanf(p1, "%d", &config.syslog_facility) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oTxpower:
			if (sscanf(p1, "%d", &config.txpower) < 1)
			{
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oNodeId:
			if (sscanf(p1, "%d", &config.nodeId) < 1)
			{
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oDistance:
			if (sscanf(p1, "%d", &config.distance) < 1)
			{
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oHeartBeat:
			if (sscanf(p1, "%d", &config.heartbeat) < 1)
			{
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oDevType:
			if (sscanf(p1, "%d", &config.devType) < 1)
			{
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oBadOption:
			debug(LOG_ERR, "Bad option %s on line %d in %s", s, linenum, filename);
			debug(LOG_ERR, "Exiting...");
			exit(-1);
			break;
		}
	}

	fclose(fd);

	debug(LOG_INFO, "Done reading configuration file '%s'", filename);
}

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean_value(char *line)
{
	if (strcasecmp(line, "no") == 0 ||
			strcasecmp(line, "false") == 0 ||
			strcmp(line, "0") == 0
	   ) {
		return 0;
	}
	if (strcasecmp(line, "yes") == 0 ||
			strcasecmp(line, "true") == 0 ||
			strcmp(line, "1") == 0
	   ) {
		return 1;
	}

	return -1;
}

/* Parse a string to see if it is valid decimal dotted quad IP V4 format */
int check_ip_format(const char *possibleip)
{
	unsigned int a1,a2,a3,a4;

	return (sscanf(possibleip,"%u.%u.%u.%u",&a1,&a2,&a3,&a4) == 4
			&& a1 < 256 && a2 < 256 && a3 < 256 && a4 < 256);
}


/* Parse a string to see if it is valid MAC address format */
int check_mac_format(const char possiblemac[])
{
	char hex2[3];
	return
		sscanf(possiblemac,
			   "%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]",
			   hex2,hex2,hex2,hex2,hex2,hex2) == 6;
}

int add_to_trusted_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC *p = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address to trust", possiblemac);
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* See if MAC is already on the list; don't add duplicates */
	for (p = config.trustedmaclist; p != NULL; p = p->next) {
		if (!strcasecmp(p->mac,mac)) {
			debug(LOG_INFO, "MAC address [%s] already on trusted list", mac);
			free(mac);
			return 1;
		}
	}

	/* Add MAC to head of list */
	p = safe_malloc(sizeof(t_MAC));
	p->mac = safe_strdup(mac);
	p->next = config.trustedmaclist;
	config.trustedmaclist = p;
	debug(LOG_INFO, "Added MAC address [%s] to trusted list", mac);
	free(mac);
	return 0;
}


/* Remove given MAC address from the config's trusted mac list.
 * Return 0 on success, nonzero on failure
 */
int remove_from_trusted_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC **p = NULL;
	t_MAC *del = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address", possiblemac);
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* If empty list, nothing to do */
	if (config.trustedmaclist == NULL) {
		debug(LOG_INFO, "MAC address [%s] not on empty trusted list", mac);
		free(mac);
		return -1;
	}

	/* Find MAC on the list, remove it */
	for (p = &(config.trustedmaclist); *p != NULL; p = &((*p)->next)) {
		if (!strcasecmp((*p)->mac,mac)) {
			/* found it */
			del = *p;
			*p = del->next;
			debug(LOG_INFO, "Removed MAC address [%s] from trusted list", mac);
			free(del);
			free(mac);
			return 0;
		}
	}

	/* MAC was not on list */
	debug(LOG_INFO, "MAC address [%s] not on  trusted list", mac);
	free(mac);
	return -1;
}


/* Given a pointer to a comma or whitespace delimited sequence of
 * MAC addresses, add each MAC address to config.trustedmaclist.
 */
void parse_trusted_mac_list(const char ptr[])
{
	char *ptrcopy = NULL, *ptrcopyptr;
	char *possiblemac = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for trusted MAC addresses", ptr);

	/* strsep modifies original, so let's make a copy */
	ptrcopyptr = ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", \t"))) {
		if (strlen(possiblemac)>0) add_to_trusted_mac_list(possiblemac);
	}

	free(ptrcopyptr);
}


/* Add given MAC address to the config's blocked mac list.
 * Return 0 on success, nonzero on failure
 */
int add_to_blocked_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC *p = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address to block", possiblemac);
		return -1;
	}

	/* abort if not using BLOCK mechanism */
	if (MAC_BLOCK != config.macmechanism) {
		debug(LOG_NOTICE, "Attempt to access blocked MAC list but control mechanism != block");
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* See if MAC is already on the list; don't add duplicates */
	for (p = config.blockedmaclist; p != NULL; p = p->next) {
		if (!strcasecmp(p->mac,mac)) {
			debug(LOG_INFO, "MAC address [%s] already on blocked list", mac);
			free(mac);
			return 1;
		}
	}

	/* Add MAC to head of list */
	p = safe_malloc(sizeof(t_MAC));
	p->mac = safe_strdup(mac);
	p->next = config.blockedmaclist;
	config.blockedmaclist = p;
	debug(LOG_INFO, "Added MAC address [%s] to blocked list", mac);
	free(mac);
	return 0;
}


/* Remove given MAC address from the config's blocked mac list.
 * Return 0 on success, nonzero on failure
 */
int remove_from_blocked_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC **p = NULL;
	t_MAC *del = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address", possiblemac);
		return -1;
	}

	/* abort if not using BLOCK mechanism */
	if (MAC_BLOCK != config.macmechanism) {
		debug(LOG_NOTICE, "Attempt to access blocked MAC list but control mechanism != block");
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* If empty list, nothing to do */
	if (config.blockedmaclist == NULL) {
		debug(LOG_INFO, "MAC address [%s] not on empty blocked list", mac);
		free(mac);
		return -1;
	}

	/* Find MAC on the list, remove it */
	for (p = &(config.blockedmaclist); *p != NULL; p = &((*p)->next)) {
		if (!strcasecmp((*p)->mac,mac)) {
			/* found it */
			del = *p;
			*p = del->next;
			debug(LOG_INFO, "Removed MAC address [%s] from blocked list", mac);
			free(del);
			free(mac);
			return 0;
		}
	}

	/* MAC was not on list */
	debug(LOG_INFO, "MAC address [%s] not on  blocked list", mac);
	free(mac);
	return -1;
}


/* Given a pointer to a comma or whitespace delimited sequence of
 * MAC addresses, add each MAC address to config.blockedmaclist
 */
void parse_blocked_mac_list(const char ptr[])
{
	char *ptrcopy = NULL, *ptrcopyptr;
	char *possiblemac = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for MAC addresses to block", ptr);

	/* strsep modifies original, so let's make a copy */
	ptrcopyptr = ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", \t"))) {
		if (strlen(possiblemac)>0) add_to_blocked_mac_list(possiblemac);
	}

	free(ptrcopyptr);
}

/* Add given MAC address to the config's allowed mac list.
 * Return 0 on success, nonzero on failure
 */
int add_to_allowed_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC *p = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address to allow", possiblemac);
		return -1;
	}

	/* abort if not using ALLOW mechanism */
	if (MAC_ALLOW != config.macmechanism) {
		debug(LOG_NOTICE, "Attempt to access allowed MAC list but control mechanism != allow");
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* See if MAC is already on the list; don't add duplicates */
	for (p = config.allowedmaclist; p != NULL; p = p->next) {
		if (!strcasecmp(p->mac,mac)) {
			debug(LOG_INFO, "MAC address [%s] already on allowed list", mac);
			free(mac);
			return 1;
		}
	}

	/* Add MAC to head of list */
	p = safe_malloc(sizeof(t_MAC));
	p->mac = safe_strdup(mac);
	p->next = config.allowedmaclist;
	config.allowedmaclist = p;
	debug(LOG_INFO, "Added MAC address [%s] to allowed list", mac);
	free(mac);
	return 0;
}


/* Remove given MAC address from the config's allowed mac list.
 * Return 0 on success, nonzero on failure
 */
int remove_from_allowed_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC **p = NULL;
	t_MAC *del = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address", possiblemac);
		return -1;
	}

	/* abort if not using ALLOW mechanism */
	if (MAC_ALLOW != config.macmechanism) {
		debug(LOG_NOTICE, "Attempt to access allowed MAC list but control mechanism != allow");
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* If empty list, nothing to do */
	if (config.allowedmaclist == NULL) {
		debug(LOG_INFO, "MAC address [%s] not on empty allowed list", mac);
		free(mac);
		return -1;
	}

	/* Find MAC on the list, remove it */
	for (p = &(config.allowedmaclist); *p != NULL; p = &((*p)->next)) {
		if (!strcasecmp((*p)->mac,mac)) {
			/* found it */
			del = *p;
			*p = del->next;
			debug(LOG_INFO, "Removed MAC address [%s] from allowed list", mac);
			free(del);
			free(mac);
			return 0;
		}
	}

	/* MAC was not on list */
	debug(LOG_INFO, "MAC address [%s] not on  allowed list", mac);
	free(mac);
	return -1;
}

/* Given a pointer to a comma or whitespace delimited sequence of
 * MAC addresses, add each MAC address to config.allowedmaclist
 */
void parse_allowed_mac_list(const char ptr[])
{
	char *ptrcopy = NULL;
	char *ptrcopyptr;
	char *possiblemac = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for MAC addresses to allow", ptr);

	/* strsep modifies original, so let's make a copy */
	ptrcopyptr = ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", \t"))) {
		if (strlen(possiblemac) > 0) {
			add_to_allowed_mac_list(possiblemac);
		}
	}

	free(ptrcopyptr);
}



/** Set the debug log level.  See syslog.h
 *  Return 0 on success.
 */
int set_log_level(int level)
{
	config.debuglevel = level;
	return 0;
}

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void
config_validate(void)
{
	config_notnull(config.gw_interface, "GatewayInterface");

	if (missing_parms) {
		debug(LOG_ERR, "Configuration is not complete, exiting...");
		exit(-1);
	}
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(const void *parm, const char parmname[])
{
	if (parm == NULL) {
		debug(LOG_ERR, "%s is not set", parmname);
		missing_parms = 1;
	}
}
