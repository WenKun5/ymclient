/*************************************************************************
    > File Name: http.h
    > Author: wenkun
    > Mail: wenkun@yunmaoinfo.com 
    > Created Time: Fri 09 May 2014 04:14:46 PM CST
 ************************************************************************/
#ifndef __HTTP_H__
#define __HTTP_H__

#define MY_HTTP_DEFAULT_PORT 80

#define BUFFER_SIZE 1024

#define HTTP_POST "POST /%s HTTP/1.1\r\nHOST: %s:%d\r\nAccept: */*\r\n"\
    "Content-Type:application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s"
#define HTTP_GET "GET /%s HTTP/1.1\r\nHOST: %s:%d\r\nAccept: */*\r\n\r\n"


struct MemoryStruct {
	char *memory;
	size_t size;
};

struct FtpFile {
  const char *filename;
  FILE *stream;
};

typedef enum http_err_code{
	HTTP_OK = 0,
	HTTP_NORMAL_ERR,
	__HTTP_ERRCODE_MAX__
}HTTP_ERR_CODE_E;

typedef  int (*http_cb)(void *, int,  int,  void *);

/**
* @brief HTTP POST请求
* @param strUrl 输入参数,请求的Url地址,如:http://www.baidu.com
* @param strPost 输入参数,使用如下格式para1=val1&para2=val2&…
* @param strResponse 输出参数,返回的内容
* @return 返回是否Post成功
*/
int http_post(const char* strUrl, const char* strPost, void* strResponse);

/**
* @brief HTTP GET请求
* @param strUrl 输入参数,请求的Url地址,如:http://www.baidu.com
* @param strResponse 输出参数,返回的内容
* @return 返回是否Post成功
*/
int http_get(const char* strUrl, http_cb cb_callback, void* data);

int http_get_data(const char* strUrl, struct MemoryStruct *data);

int http_get_file(const char* strUrl, struct FtpFile *data);

#endif
