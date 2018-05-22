/*************************************************************************
    > File Name: http.c
    > Author: wenkun
    > Mail: wenkun@yunmaoinfo.com
    > Created Time: Fri 09 May 2014 04:14:46 PM CST
 ************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include "http.h"
#include "debug.h"

static int WriteMemoryCallback(void *contents, int size, int nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL) {
    /* out of memory! */
    DEBUG(LOG_LEVEL_ERR, "not enough memory (realloc returned NULL)");
    exit(EXIT_FAILURE);
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

static int WriteFileCallback(void *buffer, int size, int nmemb, void *stream)
{
    int ret = 0;
    struct FtpFile *out = (struct FtpFile *)stream;
    if(out && !out->stream) {
    /* open file for writing */
    out->stream = fopen(out->filename, "wb");
    if(!out->stream)
      return -1; /* failure, can't open file to write */
    }
    ret = fwrite(buffer, size, nmemb, out->stream);

    fclose(out->stream);
    return ret;
}

static int http_tcpclient_create(const char *host, int port){
    struct hostent *he;
    struct sockaddr_in server_addr;
    int socket_fd;

    if((he = gethostbyname(host)) == NULL){
        return -1;
    }

   server_addr.sin_family = AF_INET;
   server_addr.sin_port = htons(port);
   server_addr.sin_addr = *((struct in_addr *)he->h_addr);

    if((socket_fd = socket(AF_INET,SOCK_STREAM,0)) == -1){
        return -1;
    }

    if(connect(socket_fd, (struct sockaddr *)&server_addr,sizeof(struct sockaddr)) == -1){
        return -1;
    }

    return socket_fd;
}

static void http_tcpclient_close(int socket){
    close(socket);
}

static int http_parse_url(const char *url,char *host,char *file,int *port){
    char *ptr1,*ptr2;
    int len = 0;
    if(!url || !host || !file || !port){
        return -1;
    }

    ptr1 = (char *)url;

    if(!strncmp(ptr1,"http://",strlen("http://"))){
        ptr1 += strlen("http://");
    }
/*
    else{
        return -1;
    }
*/
    ptr2 = strchr(ptr1,'/');
    if(ptr2){
        len = strlen(ptr1) - strlen(ptr2);
        memcpy(host,ptr1,len);
        host[len] = '\0';
        if(*(ptr2 + 1)){
            memcpy(file,ptr2 + 1,strlen(ptr2) - 1 );
            file[strlen(ptr2) - 1] = '\0';
        }
    }else{
        memcpy(host,ptr1,strlen(ptr1));
        host[strlen(ptr1)] = '\0';
    }

    //get host and ip
    ptr1 = strchr(host,':');
    if(ptr1){
        *ptr1++ = '\0';
        *port = atoi(ptr1);
    }else{
        *port = MY_HTTP_DEFAULT_PORT;
    }

    return 0;
}

static int http_tcpclient_recv(int socket,char *lpbuff){
    int recvnum = 0;

    // TODO: Can do more things
    recvnum = recv(socket, lpbuff, BUFFER_SIZE*4,0);

    return recvnum;
}

static int http_tcpclient_send(int socket,char *buff,int size){
    int tmpsnd = 0;
    int bytes_left;
    char *ptr;

    ptr = buff;
    bytes_left = size;

    while(bytes_left > 0)
    {
        tmpsnd = send(socket, ptr, bytes_left, 0);
        if(tmpsnd <= 0)
        {
            if(errno == EINTR)
                tmpsnd = 0;
            else
            {
                DEBUG(LOG_LEVEL_ERR,"Send tcp packet failed!");
                return(-1);
            }
        }
        bytes_left -= tmpsnd;
        ptr += tmpsnd;
    }

    return(size - bytes_left);
}

static int http_parse_result(const char*lpbuf, http_cb cb_func, void* userp){
    char *ptmp = NULL;
    char *response = NULL;
    int ret = 0;
    unsigned short dataLen = 0;

    ptmp = (char*)strstr(lpbuf,"HTTP/1.1");
    if(!ptmp){
        DEBUG(LOG_LEVEL_ERR,"http/1.1 not faind\n");
        return HTTP_NORMAL_ERR;
    }
    if(atoi(ptmp + 9) != 200){
        DEBUG(LOG_LEVEL_ERR,"HTTP result:\n%s\n",lpbuf);
        return HTTP_NORMAL_ERR;
    }

#if 0
    ptmp = (char*)strstr(lpbuf,"\r\n\r\n");
    if(!ptmp){
        DEBUG(LOG_LEVEL_ERR, "HTTP Content is NULL\n");
        return HTTP_NORMAL_ERR;
    }
#endif

    ptmp = (char*)strstr(lpbuf,"Content-Length");
    if(!ptmp){
        DEBUG(LOG_LEVEL_ERR, "HTTP Content is NULL\n");
        return HTTP_NORMAL_ERR;
    }
    //response = ptmp + 4;
    response = ptmp + 16;
    dataLen = strtol(response, NULL, 10);
    printf("%c,%d\n", *response, dataLen);

    ptmp = (char*)strstr(lpbuf,"\r\n\r\n");
    if(!ptmp){
        DEBUG(LOG_LEVEL_ERR, "HTTP Content is NULL\n");
        return HTTP_NORMAL_ERR;
    }

    /* Content \r\n contentLenght \r\n data */
    response = ptmp + 4;
    ret = cb_func(response, sizeof(char), dataLen, userp);
    if(ret <= 0){
        DEBUG(LOG_LEVEL_ERR, "CallBack function error: %d", ret);
        return HTTP_NORMAL_ERR;
    }

    return HTTP_OK;
}

int http_post(const char *url, const char *post_str, void* userdata){
    int socket_fd = -1;
    char lpbuf[BUFFER_SIZE*4] = {'\0'};
    char host_addr[BUFFER_SIZE] = {'\0'};
    char file[BUFFER_SIZE] = {'\0'};
    int port = 0;

    if(!url || !post_str){
        DEBUG(LOG_LEVEL_ERR, "failed!");
        return HTTP_NORMAL_ERR;
    }

    if(http_parse_url(url, host_addr, file, &port)){
        DEBUG(LOG_LEVEL_ERR, "http_parse_url failed!");
        return HTTP_NORMAL_ERR;
    }
    //printf("host_addr : %s\tfile:%s\t,%d\n",host_addr,file,port);

    socket_fd = http_tcpclient_create(host_addr, port);
    if(socket_fd < 0){
        DEBUG(LOG_LEVEL_ERR, "http_tcpclient_create failed");
        return HTTP_NORMAL_ERR;
    }

    sprintf(lpbuf, HTTP_POST, file, host_addr, port, strlen(post_str), post_str);

    DEBUG(LOG_LEVEL_DEBUG, "POST DATA: %s", post_str);
    if(http_tcpclient_send(socket_fd, lpbuf, strlen(lpbuf)) < 0){
        DEBUG(LOG_LEVEL_ERR, "http_tcpclient_send failed..\n");
        return HTTP_NORMAL_ERR;
    }

    memset(lpbuf, 0, BUFFER_SIZE*4);
    /*it's time to recv from server*/
    if(http_tcpclient_recv(socket_fd, lpbuf) <= 0){
        DEBUG(LOG_LEVEL_ERR, "http_tcpclient_recv failed\n");
        return HTTP_NORMAL_ERR;
    }

    http_tcpclient_close(socket_fd);

    return http_parse_result(lpbuf, WriteMemoryCallback, userdata);
}

int http_get(const char *url, http_cb cb_func, void* userdata)
{
    int socket_fd = -1;
    char lpbuf[BUFFER_SIZE*4] = {'\0'};
    char host_addr[BUFFER_SIZE] = {'\0'};
    char file[BUFFER_SIZE] = {'\0'};
    int port = 0;

    if(!url){
        DEBUG(LOG_LEVEL_ERR, "      failed!\n");
        return HTTP_NORMAL_ERR;
    }

    if(http_parse_url(url,host_addr,file,&port)){
        DEBUG(LOG_LEVEL_ERR, "http_parse_url failed!\n");
        return HTTP_NORMAL_ERR;
    }
    //printf("host_addr : %s\tfile:%s\t,%d\n",host_addr,file,port);

    socket_fd =  http_tcpclient_create(host_addr,port);
    if(socket_fd < 0){
        DEBUG(LOG_LEVEL_ERR, "http_tcpclient_create failed\n");
        return HTTP_NORMAL_ERR;
    }

    sprintf(lpbuf,HTTP_GET,file,host_addr,port);

    if(http_tcpclient_send(socket_fd,lpbuf,strlen(lpbuf)) < 0){
        DEBUG(LOG_LEVEL_ERR, "http_tcpclient_send failed..\n");
        return HTTP_NORMAL_ERR;
    }

    memset(lpbuf, 0, BUFFER_SIZE*4);
    if(http_tcpclient_recv(socket_fd, lpbuf) <= 0){
        DEBUG(LOG_LEVEL_ERR, "http_tcpclient_recv failed\n");
        return HTTP_NORMAL_ERR;
    }
    http_tcpclient_close(socket_fd);

    return http_parse_result(lpbuf, cb_func, userdata);
}

int http_get_data(const char* strUrl, struct MemoryStruct *data)
{
    return http_get(strUrl, WriteMemoryCallback, (void*)data);
}

int http_get_file(const char* strUrl, struct FtpFile *data)
{
    return http_get(strUrl, WriteFileCallback, (void*)data);
}
