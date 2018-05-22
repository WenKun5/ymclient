/*************************************************************************
	> File Name: ymclient.h
	> Author: wenkun
	> Mail: wenkun@yunmaoinfo.com
	> Created Time: 20150123
 ************************************************************************/
#ifndef __YMCLIENT_H__
#define __YMCLIENT_H__

//#ifdef __cplusplus
//extern "C"
//{
//#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//for get local mac
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#define ETS_URL_BASE        "http://192.168.7.1/cgi-bin/luci/etws"
//#define ETS_URL_REGISTER	ETS_URL_BASE "/register"
#define ETS_URL_HEARTBEAT	"http://192.168.1.143:5385/heartbeat"
#define ETS_URL_REGISTER	"http://192.168.1.143:5385/RegTerminal"
/******************************************************************************/
#define TRYTIMES 3
#define PARAM_TIME_SIZE 20
#define PARAM_CFGPATH_SIZE 128

#define etc_free(mem) if(NULL != (mem)) free(mem)

typedef struct etc_register_response{
	unsigned char txpower;
	unsigned int  nodeId;
	unsigned int distance;
	char time[20];
	unsigned int  downloadLimit;
	unsigned int  uploadLimit;
	unsigned char heartbeat;
}ETC_REG_RESPONSE_S;

typedef enum etc_http_event{
	ETC_REGISTER = 0,
	ETC_HEARTBEAT,
	__ETC_EVENT_MAX__
}ETC_HTTP_EVENT_E;

typedef enum etc_http_method{
	ETC_HTTP_POST = 0,
	ETC_HTTP_GET,
	ETC_HTTPS_POST,
	ETC_HTTPS_GET,
	__ETC_HTTP_MAX__
}ETC_HTTP_METHOD_E;

typedef enum etc_err_code{
	ETC_OK = 0,
	ETC_NORMAL_ERR,
	ETC_INVALID_PARAM,
	ETC_MALLOC_ERR,
	ETC_HTTP_ERR,
	__ETC_ERRCODE_MAX__
}ETC_ERR_CODE_E;

#define ETC_METHOD(_url, _handler, _name)   \
	{				    \
		.url = _url,		    \
		.handler = _handler,	    \
		.name = _name,              \
	}

typedef int (*ETC_HANDLER_T)(const char* strMsg, void* strRet, int nMsgLen);

struct etc_method{
	const char* url;
	ETC_HANDLER_T handler;
	const char* name;
};


int etc_register_request(ETC_REG_RESPONSE_S *regData);
int etc_heartbeat_request(ETC_REG_RESPONSE_S *regData);
//#ifdef __cplusplus
//}
//#endif //__cplusplus

#endif //__YMCLIENT_H__
