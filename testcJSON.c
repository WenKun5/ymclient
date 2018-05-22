#include <stdio.h>
#include <stdlib.h>                                                                                     
#include <string.h>
#include "cJSON.h"

//解析刚刚的CJSON数组
void parseArray(cJSON * pJson)
{
    if(NULL == pJson)
    {                                                                                                
        return ;
    }
    cJSON * root = pJson;
    int iSize = cJSON_GetArraySize(root);
    int iCnt = 0;
    for(iCnt = 0; iCnt < iSize; iCnt++)
    {
        cJSON * pSub = cJSON_GetArrayItem(root, iCnt);
        if(NULL == pSub)
        {
            continue;
        }

        cJSON *pSubsub = cJSON_GetObjectItem(pSub, "host");
        if(NULL == pSubsub)
        {
            //get object named "hello" faild
        }
        printf("host : %s\n", pSubsub->valuestring);

        pSubsub = cJSON_GetObjectItem(pSub, "uri");
        if(NULL == pSubsub)
        {
            //get number from json faild
        }
        printf("uri : %s\n", pSubsub->valuestring);

        pSubsub = cJSON_GetObjectItem(pSub, "adsid");
        if(NULL == pSubsub)
        {
            //get number from json faild
        }
        printf("adsid : %s\n", pSubsub->valuestring);

        pSubsub = cJSON_GetObjectItem(pSub, "adspath");
        if(NULL == pSubsub)
        {
            //get number from json faild
        }
        printf("adspath : %s\n", pSubsub->valuestring);
    }
    return;
}

int saveCfgFile(const char* filepath, char* buffer, int size)
{
    int ret = 0;
    FILE* fp = fopen(filepath, "wb");
    if(!fp)
      return -1; /* failure, can't open file to write */

    ret = fwrite(buffer, size, 1, fp);
    
    fclose(fp);
    return ret;
}

int makeJson()
{
    cJSON * pJsonRoot = NULL;

    pJsonRoot = cJSON_CreateObject();
    if(NULL == pJsonRoot)
    {
        return -1;
    }
    cJSON_AddNumberToObject(pJsonRoot, "number", 10010);

    cJSON * pArray = NULL;
    pArray = cJSON_CreateArray();
    if(NULL == pArray)
    {
        cJSON_Delete(pJsonRoot);
        return -1;
    }

    cJSON * pItem = NULL;
    pItem = cJSON_CreateObject();
    cJSON_AddStringToObject(pItem, "host", "www.baidu.com");
    cJSON_AddStringToObject(pItem, "uri", "^/$");
    cJSON_AddStringToObject(pItem, "adsid", "0001");
    cJSON_AddStringToObject(pItem, "adspath", "http://soa.gnwifi.cn/wifi/test.js");
    cJSON_AddItemToArray(pArray, pItem);
    cJSON_AddItemToObject(pJsonRoot, "target", pArray);

    //char * p = cJSON_Print(pJsonRoot);
    char * p = cJSON_PrintUnformatted(pJsonRoot);
    if(NULL == p)
    {
        cJSON_Delete(pJsonRoot);
        return -1;
    }
    int ret = saveCfgFile("./test.cfg", p, strlen(p));

    printf("%s, %d\n", p, strlen(p));
    free(p);
    cJSON_Delete(pJsonRoot);

    return ret;
}

void parseJson(char * pMsg)
{
    if(NULL == pMsg)
    {
        return;
    }
    cJSON * pJson = cJSON_Parse(pMsg);
    if(NULL == pJson)                                                                                         
    {
      return ;
    }

    // get string from json
    cJSON * pSub = cJSON_GetObjectItem(pJson, "number");
    if(NULL == pSub)
    {
        //get object named "hello" faild
    }
    printf("obj_1 : %d\n", pSub->valueint);

    // get number from json
    pSub = cJSON_GetObjectItem(pJson, "target");
    if(NULL == pSub)
    {
        //get number from json faild
    }
    parseArray(pSub);

    cJSON_Delete(pJson);
}

int main()
{
    int ret = makeJson();

   // parseJson(p);                                                                                             

    return 0;
}