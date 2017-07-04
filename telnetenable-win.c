/*
  This program is a re-implementation of the telnet console enabler utility
  for use with Netgear wireless routers.

  The original Netgear Windows binary version of this tool is available here:
  http://www.netgear.co.kr/Support/Product/FileInfo.asp?IDXNo=155

  Per DMCA 17 U.S.C. §1201(f)(1)-(2), the original Netgear executable was
  reverse engineered to enable interoperability with other operating systems
  not supported by the original windows-only tool (MacOS, Linux, etc).

        Netgear Router - Console Telnet Enable Utility
        Release 0.1 : 25th June 2006
        Copyright (C) 2006, yoshac @ member.fsf.org
        Release 0.2 : 20th August 2012
        dj bug fix on OS X
        Release 0.3 : 8th October 2012
        keithr-git bug fix to send entire packet in one write() call,
          strcpy->strncpy, clean up some whitespace

        This program is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation; either version 2 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License along
        with this program; if not, write to the Free Software Foundation, Inc.,
        51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


  The RSA MD5 and Blowfish implementations are provided under LGPL from
  http://www.opentom.org/Mkttimage
*/

//#include <netinet/tcp.h>

// #include <netinet/udp.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <netdb.h>
#include <Winsock2.h>
#include <Ws2tcpip.h>

#include <stdlib.h>
#include <stdio.h>
//#include <process.h>
#include <string.h>

#include "md5.h"
#include "blowfish.h"

#pragma comment(lib,"ws2_32.lib") //Winsock Library

static char output_buf[0x640];

static BLOWFISH_CTX ctx;

struct PAYLOAD
{
  char signature[0x10];
  char mac[0x10];
  char username[0x10];
  char password[0x21];
  char reserved[0x2F];
} payload;

void usage(char * progname)
{
  printf("\nVersion: 0.5, 2015/03/01\n");
  printf("Modified to work with newer Negear routers R7000 R7500 by insanid\n");
  printf("\nUsage:\n%s <host ip> <host mac> <user name> <password>\n\n",progname);
  exit(-1);
}

// int socket_connect(char *host, in_port_t port){
//   struct hostent *hp;
//   struct sockaddr_in addr;
//   int on = 1, sock;
// 
//   if((hp = gethostbyname(host)) == NULL){
//     herror("gethostbyname");
//     exit(1);
//   }
//   bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
//   addr.sin_port = htons(port);
//   addr.sin_family = AF_INET;
//   sock = socket(AF_INET, SOCK_DGRAM, 0);
//   setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(int));
//   if(sock == -1){
//     perror("setsockopt");
//     exit(1);
//   }
//   if(connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1){
//     perror("connect");
//     exit(1);
//   }
//   return sock;
// }

int GetOutputLength(unsigned long lInputLong)
{
  unsigned long lVal = lInputLong % 8;

  if (lVal!=0)
    return lInputLong+8-lVal;
  else
    return lInputLong;
}

int EncodeString(BLOWFISH_CTX *ctx,char *pInput,char *pOutput, int lSize)
{
  int SameDest = 0;
  int lCount;
  int lOutSize;
  int i=0;

  lOutSize = GetOutputLength(lSize);
  lCount=0;
  while (lCount<lOutSize)
    {
      char *pi=pInput;
      char *po=pOutput;
      for (i=0;i<8;i++)
        *po++=*pi++;
      Blowfish_Encrypt(ctx,(uint32_t *)pOutput,(uint32_t *)(pOutput+4));
      pInput+=8;
      pOutput+=8;
      lCount+=8;
    }

  return lCount;
}


int fill_payload(int argc, char * input[])
{
  MD5_CTX MD;
  char MD5_key[0x10];
  char secret_key[0x400]="AMBIT_TELNET_ENABLE+";
  int encoded_len;

  memset(&payload, 0, sizeof(payload));
  // NOTE: struct has .mac behind .signature and is filled here
  strcpy_s(payload.mac, sizeof(payload.mac), input[2]);
  //only works with upper case MAC address, so let's do that
  for (char* c = payload.mac; *c != 0; c++)
    *c = toupper(*c);
  strcpy_s(payload.username, sizeof(payload.username), input[3]);

  if (argc==5)
    strcpy_s(payload.password, sizeof(payload.password), input[4]);


  MD5Init(&MD);
  MD5Update(&MD,payload.mac,0x70);
  MD5Final(MD5_key,&MD);

  memcpy_s(payload.signature, sizeof(payload.signature), MD5_key, sizeof(MD5_key));
  // NOTE: so why concatenate outside of the .signature boundary again
  //       using strcat? deleting this line would keep the payload the same and not
  //       cause some funky abort() or segmentation fault on newer gcc's
  // dj: this was attempting to put back the first byte of the MAC address
  // dj: which was getting stomped by the strcpy of the MD5_key above
  // dj: a better fix is to use strncpy to avoid the stomping in the 1st place
  // MS: better fix is memcpy, since it's not a string; we are explicitly avoiding the null terminator
  //  strcat(payload.signature, input[2]);

  if (argc==5)
    strncat_s(secret_key, sizeof(secret_key), input[4], sizeof(secret_key) - strlen(secret_key) - 1);

  Blowfish_Init(&ctx,secret_key,strlen(secret_key));

  encoded_len = EncodeString(&ctx,(char*)&payload,(char*)&output_buf,0x80);

  return encoded_len;
}

u_short PORT = 23;

int main(int argc, char * argv[])
{

  int datasize;
  int sock;
  struct sockaddr_in si_other;
  WSADATA wsa;
  
  if (argc!=5)
    usage(argv[0]);

  datasize = fill_payload(argc, argv);

//   int sock = socket_connect(argv[1],PORT);
//   write(sock, output_buf, datasize);
//   close(sock);
  
  if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
  {
      printf("Failed. Error Code : %d",WSAGetLastError());
      exit(EXIT_FAILURE);
  }
  
  if ( (sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
  {
      printf("socket() failed with error code : %d" , WSAGetLastError());
      exit(EXIT_FAILURE);
  }
  
  memset((char *) &si_other, 0, sizeof(si_other));
  si_other.sin_family = AF_INET;
  si_other.sin_port = htons(PORT);
  if (inet_pton(AF_INET, argv[1], &si_other.sin_addr) != 1)
  {
    printf("inet_pton failed. Error Code : %d", WSAGetLastError());
    exit(EXIT_FAILURE);
  }

  if (sendto(sock, output_buf, datasize , 0 , (struct sockaddr *) &si_other, sizeof(si_other)) == SOCKET_ERROR)
  {
      printf("sendto() failed with error code : %d" , WSAGetLastError());
      exit(EXIT_FAILURE);
  }

  printf("\nPayload has been sent to Netgear router.\n");
  printf("Telnet should be enabled.\n\n");

  return 0;
}
