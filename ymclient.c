/*************************************************************************
    > File Name: etclient.c
    > Author: wenkun
    > Mail: wenkun@etonetech.com
    > Created Time: Fri 09 May 2018 04:14:46 PM CST
 ************************************************************************/

#include "ymclient.h"
#include "http.h"
#include "cJSON.h"
#include "debug.h"

int g_bDebug = 5;
#define POST_MAX_LEN 1024

#if 0
/*Standard Info, Json struct is {errorNum:Int, errorMessage:string}*/
/**
* @brief Check standard callback data
* @param strMsg 输入参数,待解析的报文
* @param nMsgLen 输入参数,待解析报文的长度
* @param strRet 输出参数,返回解析的errorMessage内容
* @return 返回errorNum
*/
static int etc_check_json_ret(const char* strMsg, void* strRet, int nMsgLen)
{
    cJSON *pRoot = NULL;
    cJSON *pItem = NULL;
    int nErrNum = 0;

    pRoot = cJSON_Parse((void*)strMsg);
    if (!pRoot)
    {
        DEBUG(LOG_LEVEL_ERR, "Error before:[%s]\n", cJSON_GetErrorPtr());
    }
    else
    {
        pItem = cJSON_GetObjectItem(pRoot, "errNum");
        if (pItem)
        {
            nErrNum = pItem->valueint;
        }
        pItem = cJSON_GetObjectItem(pRoot, "errMsg");
        if (pItem)
        {
            int tmpLen = strlen(pItem->valuestring);
            strncpy((char*)strRet, pItem->valuestring, (tmpLen > nMsgLen) ? nMsgLen : tmpLen);
        }

        cJSON_Delete(pRoot);
    }

    return nErrNum;
}
#endif

/**
* @brief Parse config json param list
* @param strMsg 输入参数,待解析的报文
* @param nMsgLen 输入参数,待解析报文的长度
* @param strRet 输出参数,返回解析的errorMessage内容
* @return 返回errorNum
*/
static int etc_parse_register_data(const char* strMsg, struct etc_register_response* strRet, int nMsgLen)
{
    cJSON *pRoot = NULL;
    cJSON *pItem = NULL;
    cJSON *pParam = NULL;
    int totalLen = 0;

    pRoot = cJSON_Parse(strMsg);
    if (!pRoot)
    {
        DEBUG(LOG_LEVEL_ERR, "Error before:[%s]\n", cJSON_GetErrorPtr());
        return ETC_NORMAL_ERR;
    }
    /* Get errNum */
    pItem = cJSON_GetObjectItem(pRoot, "errNum");
    //if (!pItem || pItem->valueint != 0)
    if (!pItem)
    {
	return ETC_NORMAL_ERR;
    }

    pParam = cJSON_GetObjectItem(pRoot, "data");
    if (!pParam)
    {
        DEBUG(LOG_LEVEL_ERR, "Error before:[%s]\n", cJSON_GetErrorPtr());
        return ETC_NORMAL_ERR;
    }

    pItem = cJSON_GetObjectItem(pParam, "txpower");
    if (pItem)
    {
        strRet->txpower = pItem->valueint;
        totalLen += sizeof(strRet->txpower);
    }

    pItem = cJSON_GetObjectItem(pParam, "nodeId");
    if (pItem)
    {
        strRet->txpower = pItem->valueint;
        totalLen += sizeof(strRet->nodeId);
    }

    pItem = cJSON_GetObjectItem(pParam, "distance");
    if (pItem)
    {
        strRet->txpower = pItem->valueint;
        totalLen += sizeof(strRet->distance);
    }

    pItem = cJSON_GetObjectItem(pParam, "heartbeat");
    if (pItem)
    {
        strRet->heartbeat = pItem->valueint;
        totalLen += sizeof(strRet->heartbeat);
    }

    pItem = cJSON_GetObjectItem(pParam, "downloadLimit");
    if (pItem)
    {
        strRet->downloadLimit = pItem->valueint;
        totalLen += sizeof(strRet->downloadLimit);
    }

    pItem = cJSON_GetObjectItem(pParam, "uploadLimit");
    if (pItem)
    {
        strRet->uploadLimit = pItem->valueint;
        totalLen += sizeof(strRet->uploadLimit);
    }
    cJSON_Delete(pRoot);

    //return ((totalLen > nMsgLen) ? ETC_MALLOC_ERR : ETC_OK);
    (void)nMsgLen;
    return ETC_OK;
}


static int etc_register_request_cb(const char* strMsg, void* strRet, int nMsgLen)
{
    int ret = 0;
    struct etc_register_response *pRegData;
    pRegData = (struct etc_register_response *)strRet;

    memset(pRegData, 0, sizeof(struct etc_register_response));

    ret = etc_parse_register_data((void*)strMsg, pRegData, nMsgLen);
    if (ret != ETC_OK)
    {
        DEBUG(LOG_LEVEL_ERR, "Parse config param failed! Return:%d", ret);
        return ETC_NORMAL_ERR;
    }
    return ETC_OK;
}

static int etc_heartbeat_request_cb(const char* strMsg, void* strRet, int nMsgLen)
{
    return etc_register_request_cb(strMsg, strRet, nMsgLen);
}

static void filled_register_post_data(cJSON *root)
{
    cJSON * pItem = NULL;
    pItem = cJSON_CreateObject();

/*
 cJSON_AddItemToArray: add Item to Array;
 cJSON_AddItemToObject: add Array to root;
*/
#if 0
    cJSON_AddStringToObject(pItem, "host", "www.baidu.com");
    cJSON_AddStringToObject(pItem, "uri", "^/$");
    cJSON_AddStringToObject(pItem, "adsid", "0001");
    cJSON_AddStringToObject(pItem, "adspath", "http://soa.gnwifi.cn/wifi/test.js");
    cJSON_AddItemToArray(pArray, pItem);
    cJSON_AddItemToObject(root, "target", pArray);
#endif

    cJSON_AddStringToObject(root, "opt", "register");

    cJSON_AddStringToObject(pItem, "devId", "e10adc3949ba59abbe56e057f20f883e");
    cJSON_AddStringToObject(pItem, "devType", "terminal");
    cJSON_AddStringToObject(pItem, "version", "v0.1.2");
    cJSON_AddStringToObject(pItem, "macaddr", "00:11:22:33:44:55");
    cJSON_AddStringToObject(pItem, "ipaddr", "192.168.9.1");
    cJSON_AddStringToObject(pItem, "ssid", "ETWS");
    cJSON_AddStringToObject(pItem, "nodeId", "5");
    cJSON_AddStringToObject(pItem, "time", "2018-05-18 14:30:32");
    cJSON_AddItemToObject(root, "data", pItem);

}

static void filled_hearbeat_post_data(cJSON *root)
{
    cJSON * pItem = NULL;
    cJSON * pSub = NULL;
    cJSON * pArray = NULL;
    int i = 0;
    int count = 2;

    pArray = cJSON_CreateArray();
    pItem = cJSON_CreateObject();
    pSub = cJSON_CreateObject();
/*
 cJSON_AddItemToArray: add Item to Array;
 cJSON_AddItemToObject: add Array to root;
*/
#if 0
    cJSON_AddStringToObject(pItem, "host", "www.baidu.com");
    cJSON_AddStringToObject(pItem, "uri", "^/$");
    cJSON_AddStringToObject(pItem, "adsid", "0001");
    cJSON_AddStringToObject(pItem, "adspath", "http://soa.gnwifi.cn/wifi/test.js");
    cJSON_AddItemToArray(pArray, pItem);
    cJSON_AddItemToObject(root, "target", pArray);
#endif

    cJSON_AddStringToObject(root, "opt", "heartbeat");

    cJSON_AddStringToObject(pItem, "devId", "e10adc3949ba59abbe56e057f20f883e");
    cJSON_AddStringToObject(pItem, "devType", "terminal");
    cJSON_AddStringToObject(pItem, "version", "v0.1.2");
    cJSON_AddStringToObject(pItem, "macaddr", "00:11:22:33:44:55");
    cJSON_AddStringToObject(pItem, "ipaddr", "192.168.9.1");
    cJSON_AddStringToObject(pItem, "ssid", "ETWS");
    cJSON_AddStringToObject(pItem, "nodeId", "5");
    cJSON_AddStringToObject(pItem, "time", "2018-05-18 14:30:32");

    cJSON_AddStringToObject(pSub, "uptime", "1min25s");
    cJSON_AddStringToObject(pSub, "txbytes", "1000");
    cJSON_AddStringToObject(pSub, "txpkgs", "1000");
    cJSON_AddStringToObject(pSub, "rxbytes", "100");
    cJSON_AddStringToObject(pSub, "rxpkgs", "1500");
    cJSON_AddStringToObject(pSub, "txpower", "12");
    cJSON_AddItemToObject(pItem, "sysinfo", pSub);

    cJSON_AddNumberToObject(pItem, "staNum", count);

    for (i = 0; i < count; ++i)
    {
        cJSON *pTmp = NULL;
        pTmp = cJSON_CreateObject();
        cJSON_AddStringToObject(pTmp, "macaddr", "11:22:33:44:55:66");
        cJSON_AddStringToObject(pTmp, "ipaddr", "192.168.8.10");
        cJSON_AddNumberToObject(pTmp, "signal", 65+i);
        cJSON_AddStringToObject(pTmp, "txbytes", "1000");
        cJSON_AddStringToObject(pTmp, "rxbytes", "1600");
        cJSON_AddItemToArray(pArray, pTmp);
    }

    cJSON_AddItemToObject(pItem, "stalist", pArray);
    cJSON_AddItemToObject(root, "data", pItem);
}


static const struct etc_method event_methods[__ETC_EVENT_MAX__] = {
    [ETC_REGISTER]      = ETC_METHOD(ETS_URL_REGISTER, etc_register_request_cb, "ETC_REGISTER"),
    [ETC_HEARTBEAT]     = ETC_METHOD(ETS_URL_HEARTBEAT, etc_heartbeat_request_cb, "ETC_HEARTBEAT"),
};

static int filled_up_post_data(char* strPost, ETC_HTTP_EVENT_E event)
{
    char *out = NULL;
    cJSON *root = NULL;

    root = cJSON_CreateObject();//JSON数据根节点
    if (NULL == root)
    {
        return ETC_NORMAL_ERR;
    }

    switch(event){
        case ETC_REGISTER:
            filled_register_post_data(root);
            break;
        case ETC_HEARTBEAT:
            filled_hearbeat_post_data(root);
            break;
        default:
            DEBUG(LOG_LEVEL_ERR, "Get error event number:%d", event);
            break;
    }
    out = cJSON_Print(root);
    if (NULL == out)
    {
        cJSON_Delete(root);
        return ETC_NORMAL_ERR;
    }
    sprintf(strPost, "%s", out);
    free(out);
    cJSON_Delete(root);
    return ETC_OK;
}

static int etc_http_event_handle(ETC_HTTP_EVENT_E event, char* strUrl, char* strArgv, void* strRet)
{
    char strPost[POST_MAX_LEN] = {0};
    char ret = 0;
    struct MemoryStruct sResponse;
    const char* dstUrl = NULL;
    const char* eventName = NULL;

    /*1. 检查输入参数*/
    if(event < ETC_REGISTER || event >= __ETC_EVENT_MAX__)
    {
        DEBUG(LOG_LEVEL_ERR, "Input params is invalid! event:%d", event);
        return ETC_INVALID_PARAM;
    }

    DEBUG(LOG_LEVEL_INFO, "Fill up post data.");
    /*2. 组合post数据*/
    ret = filled_up_post_data(strPost, event);
    if (ETC_OK != ret)
    {
        DEBUG(LOG_LEVEL_ERR, "Fill up post data failed! Err:%d", ret);
        return ETC_HTTP_ERR;
    }

    DEBUG(LOG_LEVEL_INFO, "Before send post.");
    /*2. 组合post数据*/
    /*3. 调用http_post发送请求*/
    sResponse.memory = malloc(1);  /* will be grown as needed by the realloc above */
    sResponse.size = 0;            /* no data at this point */
    dstUrl = event_methods[event].url;
    eventName = event_methods[event].name;

    DEBUG(LOG_LEVEL_DEBUG, "Request:[%s], URL:%s!", eventName, dstUrl);
    ret = http_post(dstUrl, strPost, (void*)&sResponse);
    if (HTTP_OK != ret)
    {
        etc_free(sResponse.memory);
        DEBUG(LOG_LEVEL_ERR, "%s post to %s failed! Err:%d", eventName, dstUrl, ret);
        return ETC_HTTP_ERR;
    }

    /*4. 检查云端返回数据*/
    ret = event_methods[event].handler(sResponse.memory, strRet, sResponse.size);
    DEBUG(LOG_LEVEL_DEBUG, "Response:[%s], %s.", eventName, sResponse.memory);
    if (ETC_OK != ret)
    {
        etc_free(sResponse.memory);
        DEBUG(LOG_LEVEL_ERR, "%s check return failed! Err:%d", eventName, ret);
        return ETC_HTTP_ERR;
    }

    etc_free(sResponse.memory);
    return ETC_OK;
}

/* Send register info to server*/
int etc_register_request(ETC_REG_RESPONSE_S *regData)
{
    return etc_http_event_handle(ETC_REGISTER, NULL, NULL, regData);
}

/* Send register info to server*/
int etc_heartbeat_request(ETC_REG_RESPONSE_S *regData)
{
    return etc_http_event_handle(ETC_HEARTBEAT, NULL, NULL, regData);
}

#if 0
/* Send ads render result to server*/
int etc_report_result(char* devId , char* status, int* result)
{
    return etc_http_event_handle(ETC_REPORT_RESULT, devId, status, result);
}

/* Send request to check user authentication status*/
int etc_check_auth(char* devId , char* status, ETC_AUTH_RESPONSE_S *authData)
{
    return etc_http_event_handle(ETC_REPORT_RESULT, devId, status, authData);
}
#endif
