/*************************************************************************
    > File Name: etws_sys.c
    > Author: wenkun
    > Mail: wenkun@etonetech.com
    > Created Time: Fri 09 May 2014 04:14:46 PM CST
 ************************************************************************/
#include <common.h>
#include "etws_sys.h"


/**
* @brief 获取指定网络设备的MAC地址
* @param macaddr 输出参数,返回MAC地址
* @return 返回是否获取MAC成功, 0表示成功
*/
static int sys_get_mac(char* devName, char* macaddr)
{
    struct ifreq  ifreq;
    unsigned char mac[6] = {0};
    int   sock;
    int i = 0;

    if((sock=socket(AF_INET,SOCK_STREAM,0)) <0)
    {
        perror( "socket ");
        return  ETWS_NORMAL_ERR;
    }
    strcpy(ifreq.ifr_name, devName);
    if(ioctl(sock, SIOCGIFHWADDR, &ifreq) <0)
    {
        perror( "ioctl ");
        return  ETWS_NORMAL_ERR;
    }

    for (i = 0; i < 6; ++i)
    {
        mac[i] = (unsigned char)ifreq.ifr_hwaddr.sa_data[i];
    }

    sprintf(macaddr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return ETWS_OK;
}

/**
* @brief 获取设备唯一标识码
* @param devId 输出参数,返回设备唯一标识码
* @return 返回是否获取唯一标识码成功, 0表示成功
*/
static int sys_get_devId(char* devId)
{
	return ETWS_OK;
}

/**
* @brief 获取设备软件版本信息
* @param version 输出参数,返回设备版本信息
* @return 返回是否设备版本信息是否成功, 0表示成功
*/
static int sys_get_version(char *version)
{
	return ETWS_OK;
}

/**
* @brief 获取设备IP地址
* @param ipaddr 输出参数,返回设备ip地址
* @return 返回是否设备IP地址, 0表示成功
*/
static int sys_get_mesh_ip(char *ipaddr)
{
	return ETWS_OK;
}

/**
* @brief 获取设备连接的终端列表信息
* @param station list 输出参数,返回设备ip地址
* @return 返回是否设备IP地址, 0表示成功
*/
static int sys_get_sta_list()
{

	return ETWS_OK;
}