/* Quansheng UV-K5 EEPROM programmer v0.9 
 * (c) 2023 Jacek Lipkowski <sq5bpf@lipkowski.org>
 *
 * This program can read and write the eeprom of Quansheng UVK5 Mark II 
 * and probably other similar radios via the serial port. 
 *
 * It can read/write arbitrary data, and might be useful for reverse
 * engineering the radio configuration.
 *
 * It can also flash you radio, which has a very high probability of
 * permanently breaking your radio. The flash image is an unencrypted
 * image, without the version inserted at 0x2000.
 *
 * Use at your own risk. 
 *
 *
 * This program is licensed under the GNU GENERAL PUBLIC LICENSE v3
 * License text avaliable at: http://www.gnu.org/copyleft/gpl.html 
 */

/*
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <ctype.h>
#include <stdint.h>
#include "uvk5.h"

#define VERSION "Quansheng UV-K5 EEPROM programmer v0.9 (c) 2023 Jacek Lipkowski <sq5bpf@lipkowski.org>"

#define MODE_NONE 0
#define MODE_READ 1
#define MODE_WRITE 2
#define MODE_WRITE_MOST 3
#define MODE_WRITE_ALL 4
#define MODE_FLASH_DEBUG 5
#define MODE_FLASH 6


#define UVK5_EEPROM_SIZE 0x2000
#define UVK5_EEPROM_SIZE_WITHOUT_CALIBRATION 0x1d00
#define UVK5_EEPROM_BLOCKSIZE 0x80
#define UVK5_PREPARE_TRIES 10

/* actually the flash is bigger, but there is a bootloader at 0xf000 that we don't want to overwrite 
 * if you're really brave, then you can modify the code by changing UVK5_MAX_FLASH_SIZE to 0x10000
 * and probably flash the bootloader too, but i would really advise against doing this
 *
 * maybe at some point i will make a command line flag for this
 */
#define UVK5_MAX_FLASH_SIZE 0xf000 
#define UVK5_FLASH_BLOCKSIZE 0x100

#define DEFAULT_SERIAL_PORT "/dev/ttyUSB0"
#define DEFAULT_FILE_NAME "k5_eeprom.raw"
#define DEFAULT_FLASH_NAME "k5_flash.raw"

/* the vendor flasher sends the firmware version like "2.01.23" */
#define DEFAULT_FLASH_VERSION "*.01.23"

/* globals */
speed_t ser_speed=B38400;
char *ser_port=DEFAULT_SERIAL_PORT;
int verbose=0;
int mode=MODE_NONE;
char *file=DEFAULT_FILE_NAME;
char *flash_file=DEFAULT_FLASH_NAME;

char flash_version_string[8]=DEFAULT_FLASH_VERSION;

int write_offset=0;
int write_length=-1;

int i_know_what_im_doing=0; /* flag the user sets to confirm that he thinks he knows what he's doing */

struct k5_command {
	unsigned char *cmd;
	int len;
	unsigned char *obfuscated_cmd;
	int obfuscated_len;
	int crcok;
};

/**** commands ********/
unsigned char uvk5_hello2[]={0x14, 0x05, 0x04, 0x00, 0x9f, 0x25, 0x5a, 0x64}; 

/* commands:
 * 0x14 - hello
 * 0x1b - read eeprom
 * 0x1d - write eeprom
 * 0xdd - reset radio
 */

/*
 * flash commands:
 * 0x30 - say hello to the radio and present the version (reply is also 0x18)
 * 0x19 - send flash block (reply from radio is 0x1a)
 *
 * from the radio:
 * 0x18 - broadcast from the radio when flash mode is enabled
 * 
 *
 */

/* the last 6 bytes have to be the same for each "session" */
unsigned char uvk5_hello[]={ 0x14,  0x5,  0x4,  0x0,  0x6a,  0x39,  0x57,  0x64 };
unsigned char uvk5_readmem1[]={ 0x1b,  0x5,  0x8,  0x0,  0x80,  0xe,  0x80,  0x0,  0x6a,  0x39,  0x57,  0x64 }; /* byte6 - length (max 0x80), byte 4 (lsb) ,5 (msb)  address */
unsigned char uvk5_writemem1[]={ 0x1d, 0x5, 0x18, 0x0, 0x50, 0xf, 0x10, 0x0, 0x14, 0xad, 0x5c, 0x64, 0x43, 0x48, 0x30, 0x30, 0x31, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }; /* byte3 - command length, byte6 - data to be written length, byte4 - (lsb) byte5( msb) address, byte12-end data */

unsigned char uvk5_reset[]={ 0xdd,  0x5,  0x0,  0x0 };

/* terrible hexdump ripped from some old code, please don't look */
void hdump(unsigned char *buf,int len)
{
	int tmp1;
	char adump[80];
	int tmp2=0;
	int tmp3=0;
	unsigned char sss;
	char hexz[]="0123456789abcdef";

	int lasttmp=0;

	printf("\n0x%6.6x |0 |1 |2 |3 |4 |5 |6 |7 |8 |9 |a |b |c |d |e |f |\n",len);
	printf("---------+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+------------\n");

	memset(&adump,' ',78);
	adump[78]=0;

	for (tmp1=0; tmp1<len; tmp1++)
	{
		tmp2=tmp1%16;
		if (tmp2==0) {
			if (tmp1!=0)  { printf("0x%6.6x: %.69s\n",tmp3,adump); lasttmp=tmp1; }
			memset(&adump,' ',78);
			adump[78]=0;
			tmp3=tmp1;
		}
		sss=buf[tmp1];
		adump[tmp2*3]=hexz[sss/16];
		adump[tmp2*3+1]=hexz[sss%16];

		if (isprint(sss)) { adump[tmp2+50]=sss; } else adump[tmp2+50]='.';
	}
	//if (((tmp1%16)!=0)||(len==16)) printf("0x%6.6x: %.69s\n",tmp3,adump);
	if (lasttmp!=tmp1) printf("0x%6.6x: %.69s\n",tmp3,adump);
}

int openport(char *port,speed_t speed)
{
	int fd;
	struct termios my_termios;

	fd = open(port, O_RDWR | O_NOCTTY);

	if (fd < 0)
	{
		printf("open error %d %s\n", errno, strerror(errno));
		return(-1);
	}

	if (tcgetattr(fd, &my_termios))
	{
		printf("tcgetattr error %d %s\n", errno, strerror(errno));
		return(-1);
	}

	if (tcflush(fd, TCIFLUSH))
	{
		printf("tcgetattr error %d %s\n", errno, strerror(errno));
		return(-1);
	}


	my_termios.c_cflag =  CS8 |CREAD | CLOCAL | HUPCL;
	cfmakeraw(&my_termios);
	cfsetospeed(&my_termios, speed);
	if (	tcsetattr(fd, TCSANOW, &my_termios))
	{
		printf("tcsetattr error %d %s\n", errno, strerror(errno));
		return(-1);
	}


	return(fd);

}

/* read with timeout */
int read_timeout(int fd, unsigned char *buf, int maxlen, int timeout)
{
	fd_set rfd;
	int len=0;
	int ret;
	struct timeval tv;
	int nr;
	unsigned char *buf2;
	buf2=buf;
	FD_ZERO(&rfd);

	while(1) {
		FD_SET(fd,&rfd);
		tv.tv_sec=timeout/1000;
		tv.tv_usec=(timeout%1000)/1000;

		ret=select(fd+1,&rfd,0,0,&tv);

		if (FD_ISSET(fd,&rfd)) {
			nr=read(fd,buf,maxlen);

			len=len+nr;
			buf=buf+nr;
			if (nr>=0) maxlen=maxlen-nr;
			if (maxlen==0) break;
		} 


		if (ret==0)  {
			fprintf(stderr,"read_timeout\n");
			/* error albo timeout */
			break;
		}

	}
	if (verbose>2) {
		printf("RXRXRX:\n");
		hdump(buf2,len);
	}

	return(len);
}



void destroy_k5_struct(struct k5_command *cmd)
{
	if (cmd->cmd) { free(cmd->cmd); }
	if (cmd->obfuscated_cmd) { free(cmd->obfuscated_cmd); }
	free(cmd);
}

/* ripped from https://mdfs.net/Info/Comp/Comms/CRC16.htm */
uint16_t crc16xmodem(unsigned char *addr, int num, int crc)
{
#define poly 0x1021
	int i;

	for (; num>0; num--)               /* Step through bytes in memory */
	{
		crc = crc ^ (*addr++ << 8);      /* Fetch byte from memory, XOR into CRC top byte*/
		for (i=0; i<8; i++)              /* Prepare to rotate 8 bits */
		{
			crc = crc << 1;                /* rotate */
			if (crc & 0x10000)             /* bit 15 was set (now bit 16)... */
				crc = (crc ^ poly) & 0xFFFF; /* XOR with XMODEM polynomic */
			/* and ensure CRC remains 16-bit value */
		}                              /* Loop for 8 bits */
	}                                /* Loop until num=0 */

	return(crc);                     /* Return updated CRC */
}


/* (de)obfuscate the string using xor */
void xorarr(unsigned char *inarr,int len)
{
	int len2=0;
	unsigned char k5_xor_array[16]= { 
		0x16 , 0x6c , 0x14 , 0xe6 , 0x2e , 0x91 , 0x0d , 0x40 ,
		0x21 , 0x35 , 0xd5 , 0x40 , 0x13 , 0x03 , 0xe9 , 0x80 };

	while (len2<len) {
		*inarr=*inarr^k5_xor_array[len2%sizeof(k5_xor_array)];
		len2++;
		inarr++;
	}
}

/* hexdump a k5_command struct */
void k5_hexdump(struct k5_command *cmd) {
	printf ("********  k5 command hexdump [obf_len:%i clear_len:%i crc_ok:%i **********\n",cmd->obfuscated_len,cmd->len,cmd->crcok);
	if (cmd->obfuscated_cmd) {
		printf("## obfuscated ##\n");
		hdump(cmd->obfuscated_cmd,cmd->obfuscated_len);
	}
	if (cmd->cmd) {
		printf("## cleartext ##\n");
		hdump(cmd->cmd,cmd->len);
	}
	printf("*****************\n");
}


/* obfuscate a k5 datagram */
int k5_obfuscate(struct k5_command *cmd)
{
	uint16_t c;
	if (!cmd->cmd) return(0);
	if (cmd->obfuscated_cmd) { free (cmd->obfuscated_cmd); }
	cmd->obfuscated_len=cmd->len+8; /* header  + length + data + crc + footer */
	cmd->obfuscated_cmd=calloc(cmd->obfuscated_len,1);
	cmd->obfuscated_cmd[0]=0xab;
	cmd->obfuscated_cmd[1]=0xcd;
	cmd->obfuscated_cmd[2]=(cmd->len)&0xff;
	cmd->obfuscated_cmd[3]=(cmd->len>>8)&0xff;
	memcpy((cmd->obfuscated_cmd)+4,cmd->cmd,cmd->len);
	c=crc16xmodem((cmd->obfuscated_cmd)+4,cmd->len,0);
	cmd->obfuscated_cmd[cmd->len+4]=c&0xff;
	cmd->obfuscated_cmd[cmd->len+5]=(c>>8)&0xff;
	xorarr((cmd->obfuscated_cmd)+4,cmd->len+2);
	cmd->obfuscated_cmd[cmd->len+6]=0xdc;
	cmd->obfuscated_cmd[cmd->len+7]=0xba;
	cmd->crcok=1;
	return(1);
}

/* deobfuscate a k5 datagram and verify it */
int k5_deobfuscate(struct k5_command *cmd)
{
	uint16_t c,d;

	if (!cmd->obfuscated_cmd) return(0);
	if (cmd->cmd) { free (cmd->cmd); }
	/* check the obfuscated datagram */
	if ((cmd->obfuscated_cmd[0]!=0xab)||(cmd->obfuscated_cmd[1]!=0xcd)) { 
		//bad header
		if (verbose>2)	{ printf("bad header\n"); k5_hexdump(cmd); }
		return(0); 
	} 
	if ((cmd->obfuscated_cmd[cmd->obfuscated_len-2]!=0xdc)||(cmd->obfuscated_cmd[cmd->obfuscated_len-1]!=0xba)) { 
		//bad footer
		if (verbose>2)	{ printf("bad footer\n"); k5_hexdump(cmd); }
		return(0); 
	} 
	cmd->len=cmd->obfuscated_len-6; /* header  + length + data + crc + footer */
	cmd->cmd=calloc(cmd->len,1);
	memcpy(cmd->cmd,cmd->obfuscated_cmd+4,cmd->len);
	xorarr(cmd->cmd,cmd->len);
	c=crc16xmodem(cmd->cmd,cmd->len-2,0);
	d=(cmd->cmd[cmd->len-2])|(cmd->cmd[cmd->len-1]<<8);
	//if ((*cmd->cmd[*cmd->cmd-2]==(c&0xff))&&(*cmd->cmd[*cmd->cmd-2]==((c<<8)&0xff)))
	/* the protocol looks like it would use crc from the radio to the pc, but instead the radio sends 0xffff */
	if (d==0xffff)
	{
		cmd->crcok=1;
		cmd->len=cmd->len-2; /* skip crc */
	} else {
		if (d==c) {
			printf("** the protocol actually uses proper crc on datagrams from the radio, please inform the author of the radio/firmware version\n");
			k5_hexdump(cmd);
		} 
		cmd->crcok=0;
		if (verbose>2)	{ printf("bad crc 0x%4.4x (should be 0x%4.4x)\n",d,c); k5_hexdump(cmd); }
		cmd->len=cmd->len-2; /* skip crc */
		return(0); 

	}
	return(1);
}

/* obfuscate a command, send it */
int k5_send_cmd(int fd,struct k5_command *cmd) {
	int l;

	if (!k5_obfuscate(cmd)) { 
		fprintf(stderr,"obfuscate error!\n");
		return(0);
	}

	if (verbose>1) k5_hexdump(cmd);

	l=write(fd,cmd->obfuscated_cmd,cmd->obfuscated_len);
	if (verbose>2) printf("write %i\n",l);
	return(1);
}

int k5_send_buf(int fd,unsigned char *buf,int len) {
	int l;
	struct k5_command *cmd;

	cmd=calloc(sizeof(struct k5_command),1);
	cmd->len=len;
	cmd->cmd=malloc(cmd->len);
	memcpy(cmd->cmd,buf,len);
	l=k5_send_cmd(fd,cmd);
	destroy_k5_struct(cmd);
	return(l);
}

/* receive a response, deobfuscate it */
struct k5_command *k5_receive(int fd,int tmout) {
	unsigned char buf[4];
	struct k5_command *cmd;
	int len;

	len=read_timeout(fd,(unsigned char *)&buf,sizeof(buf),10000); /* wait 500ms */

	if (len>0) {
		if (verbose>2)	{ printf("magic:\n"); hdump((unsigned char *)&buf,len); }
	} else
	{
		fprintf(stderr,"k5_receive: err read1\n");
		return(0);
	}


	if ((buf[0]!=0xab)||(buf[1]!=0xcd)) {
		fprintf(stderr,"k5_receive: bad magic number\n");
		return(0);
	}

	if (buf[3]!=0) {
		fprintf(stderr,"k5_receive: it seems that byte 3 can be something else than 0, please notify the author\n");
		return(0);
	}

	cmd=calloc(sizeof(struct k5_command),1);
	cmd->obfuscated_len=buf[2]+8;
	cmd->obfuscated_cmd=calloc(cmd->obfuscated_len,1);
	memcpy(cmd->obfuscated_cmd,buf,4);
	len=read_timeout(fd,cmd->obfuscated_cmd+4,buf[2]+4,tmout); /* wait 500ms */
	if ((len+4)!=(cmd->obfuscated_len)) {
		fprintf(stderr,"k5_receive err read1 len=%i wanted=%i\n",len,cmd->obfuscated_len);
		return(0);
	}


	/* deobfuscate */
	k5_deobfuscate(cmd);
	if (verbose>2)	k5_hexdump(cmd);
	return(cmd);
}
/******************************/
/*  eeprom read/write support */
/******************************/
int k5_readmem(int fd, unsigned char *buf, unsigned char maxlen, int offset)
{
	unsigned char readmem[sizeof(uvk5_readmem1)];


	int r;
	struct k5_command *cmd;

	if (verbose>1) 	printf("@@@@@@@@@@@@@@@@@@     readmem offset=0x%4.4x len=0x%2.2x\n",offset,maxlen);
	/* byte6 - length (max 0x80), byte 4 (lsb) ,5 (msb)  address */
	memcpy(readmem,uvk5_readmem1,sizeof(uvk5_readmem1));
	readmem[6]=maxlen;
	readmem[4]=offset&0xff;
	readmem[5]=(offset>>8)&0xff;


	r=k5_send_buf(fd,readmem,sizeof(readmem));
	if (!r) return(0);
	cmd=k5_receive(fd,10000);
	if (!cmd) return(0);


	if (verbose>2) k5_hexdump(cmd);

	memcpy(buf,cmd->cmd+8,cmd->len-8);
	destroy_k5_struct(cmd);
	return(1);

}

int k5_writemem(int fd, unsigned char *buf, unsigned char len, int offset)
{
	unsigned char writemem[512];


	int r;
	struct k5_command *cmd;

	if (verbose>1) printf("@@@@@@@@@@@@@@@@@@     writemem offset=0x%4.4x len=0x%2.2x\n",offset,len);
	/* byte6 - length (max 0x80), byte 4 (lsb) ,5 (msb)  address */


	writemem[0]=0x1d;
	writemem[1]=0x5;
	writemem[2]=len+8;
	writemem[3]=0;
	writemem[4]=offset&0xff;
	writemem[5]=(offset>>8)&0xff;
	writemem[6]=len;
	writemem[7]=1;

	writemem[8]=0x6a;
	writemem[9]=0x39;
	writemem[10]=0x57;
	writemem[11]=0x64;

	memcpy((void *)&writemem+12,buf,len);

	r=k5_send_buf(fd,writemem,len+12);
	if (!r) return(0);

	cmd=k5_receive(fd,10000);
	if (!cmd) return(0);

	if (verbose>2) k5_hexdump(cmd);

	if (((cmd->cmd[0])!=0x1e)||((cmd->cmd[4])!=writemem[4])||((cmd->cmd[5])!=writemem[5])) {
		fprintf(stderr,"bad write confirmation\n");
		destroy_k5_struct(cmd);
		return(0);
	}

	destroy_k5_struct(cmd);
	return(1);
}

/* reset the radio */
int k5_reset(int fd)
{
	int r;

	if (verbose>1) printf("@@@@@@@@@@@@@@@@@@    reset\n");
	r=k5_send_buf(fd,uvk5_reset,sizeof(uvk5_reset));
	return(r);
}	
/*  end of eeprom read/write support */


/******************************/
/*  flash read/write support */
/******************************/

/* wait for a "i'm in flashing mode" message */
int wait_flash_message(int fd,int ntimes) {
	struct k5_command *cmd;
	int ok=0;
	char buf[17];
	int i,j;

	while(ntimes) {
		ntimes--;

		if (verbose>1) { printf("wait_flash_message try %i\n",ntimes); }

		cmd=k5_receive(fd,10000);

		if (!cmd) {
			printf("wait_flash_message: timeout\n");
			continue; 
		}

		k5_hexdump(cmd);

		if (!cmd->cmd) {
			printf("wait_flash_message: received malformed packet\n");
			destroy_k5_struct(cmd);
			continue;
		}

		if (cmd->cmd[0]!=0x18) {
			printf("wait_flash_message: got unexpected command type 0x%2.2x\n",cmd->cmd[0]);
			destroy_k5_struct(cmd);
			continue;
		}
		/* 36 is normal length, 22 is sent by some LSENG UV-K5 clone, 
		 * 20 is sent by some other version, so just use an arbitrarily chosen range */
		if ((cmd->len<18)||(cmd->len>50)) {
			printf("wait_flash_message: got unexpected command length %i\n",cmd->len);
			destroy_k5_struct(cmd);
			continue;
		}

		/*
		 * this is what a "i'm in flashing mode" packet looks like
		 *
		 * 
		 *  0x000024 |0 |1 |2 |3 |4 |5 |6 |7 |8 |9 |a |b |c |d |e |f |
		 *  ---------+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+------------
		 *  0x000000: 18 05 20 00 01 02 02 06 1c 53 50 4a 37 47 ff 0f   .. ......SPJ7G..   
		 *  0x000010: 8c 00 53 00 32 2e 30 30 2e 30 36 00 34 0a 00 00   ..S.2.00.06.4...   
		 *  0x000020: 00 00 00 20                                       ...                
		 */

		if (
			((cmd->cmd[2]!=0x20)||(cmd->cmd[3]!=0x0)||(cmd->cmd[4]!=0x1)||(cmd->cmd[5]!=0x2)||(cmd->cmd[6]!=0x2))
			&&
			((cmd->cmd[9]!=0x53)||(cmd->cmd[10]!=0x50)||(cmd->cmd[11]!=0x4a)||(cmd->cmd[12]!=0x37)||(cmd->cmd[13]!=0x47))
		) {
			printf("wait_flash_message: got unexpected packet contents\n");
			destroy_k5_struct(cmd);
			continue;
		}

		/* all is good, so break */
		ok=1; 	break;


	}

	if (!ok) {
		printf("wait_flash_message: no flash message from radio\n");
		return(0);
	}

	for (i=0;i<(sizeof(buf)-1);i++) {
		j=i+0x14;
		if (j>=cmd->len) break;
		if (!isprint(cmd->cmd[j])) break;
		buf[i]=cmd->cmd[j];
	}
	buf[i]=0;
	printf("Flasher version is: [%s]\n",buf);
	destroy_k5_struct(cmd);
	return(1);
}

/* sends the version of firmware that we will be flashing, 
 * unobfuscated firmware will have the version number in 16 bytes at 0x2000
 * probably these bytes are sent.
 *
 * the vendor flasher sends the real version,  something like  2.01.23
 * if we send a * as the first character, then all known bootloaders
 * will accept it
 */
int k5_send_flash_version_message(int fd,char *version_string) {

	int r;
	struct k5_command *cmd;
	//unsigned char uvk5_flash_version[]={ 0x30, 0x5, 0x10, 0x0, '2', '.', '0', '1', '.', '2', '3', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	unsigned char uvk5_flash_version[]={ 0x30, 0x5, 0x10, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	strncpy ((char *)&uvk5_flash_version+4,flash_version_string,8);
	r=k5_send_buf(fd,uvk5_flash_version,sizeof(uvk5_flash_version));
	if (!r) return(0);

	/* check if we're still getting packets, usually this is a 0x18 type packet, but not sure what else the radio can send  */
	cmd=k5_receive(fd,10000);
	if (!cmd) return(0);

	if (verbose>1) k5_hexdump(cmd);
	destroy_k5_struct(cmd);

	return(1);
}

int k5_writeflash(int fd, unsigned char *buf, int  len, int offset,int max_flash_addr)
{
	int l;
	unsigned char writeflash[512];

	int ok=0;

	int r;
	struct k5_command *cmd;

	if (verbose>1) printf("@@@@@@@@@@@@@@@@@@     writeflash offset=0x%4.4x len=0x%2.2x\n",offset,len);
	memset(writeflash,0,sizeof(writeflash));

	/* 0x19  0x5  0xc  0x1  0x8a  0x8d  0x9f  0x1d  
	 * address_msb  address_lsb  0xe6  0x0  length_msb  length_lsb  0x0  0x0 
	 * [0x100 bytes of data, if length is <0x100 then fill the rest with zeroes] */
	writeflash[0]=0x19;
	writeflash[1]=0x5;
	/* bytes 2,3: length is 0x10c */
	writeflash[2]=0xc;
	writeflash[3]=1; 
	writeflash[4]=0x8a;
	writeflash[5]=0x8d;
	writeflash[6]=0x9f;
	writeflash[7]=0x1d;

	writeflash[8]=(offset>>8)&0xff;
	writeflash[9]=offset&0xff;
	//writeflash[10]=0xe6;
	writeflash[10]=(max_flash_addr>>8)&0xff;
	writeflash[11]=0x00;
	//writeflash[11]=max_flash_addr&0xff;
	writeflash[12]=len&0xff;
	writeflash[13]=(len>>8)&0xff;
	writeflash[14]=0x00;
	writeflash[15]=0x00;

	memcpy((void *)&writeflash+16,buf,len);

	r=k5_send_buf(fd,writeflash,0x100+16); /* we always send 0x100 bytes, header is 16 bytes */
	if (!r) return(0);

	/* wait for a reply packet */
	l=5;
	while(l) {
		cmd=k5_receive(fd,10000);
		l--;
		if (!cmd) { 
			usleep(1000); 
			continue;
		}

		if (verbose>1) {
			printf("|||||  reply packet after flash command\n");
			k5_hexdump(cmd);
		}
		/* we're still getting "i'm in flash mode packets", can happen after the first flash command, ignore it */
		if ((cmd->cmd[0]==0x18)&&(cmd->cmd[1]==0x05)&&(cmd->cmd[2]==0x20)&&(cmd->cmd[3]==0x0)&&(cmd->cmd[4]==0x1)&&(cmd->cmd[5]==0x2)&&(cmd->cmd[6]==0x2)) {
			if (verbose>1)  printf("&&&&|  ignoring \"i'm in flash mode\" packet\n");
			destroy_k5_struct(cmd);
			continue;
		}


		/* reply packet:
		 * 0x1a  0x5  0x8  0x0  0x8a  0x8d  0x9f  0x1d  0x0  0x0  0x0  0x0
		 */
		if (((cmd->cmd[0])!=0x1a)||((cmd->cmd[8])!=writeflash[8])||((cmd->cmd[9])!=writeflash[9])) {
			fprintf(stderr,"bad write confirmation\n");
			destroy_k5_struct(cmd);
			continue;
		}
		ok=1; 
		destroy_k5_struct(cmd);
		break;
	}

	if (!ok) {
		printf("\n\nERROR: no confirmation for flash block 0x%4.4x, length 0x%4.4x\n\n",offset,len);
		/* TODO: what do we do if there wasn't a proper confirmation? retry maybe? */
	}
	return(ok);
}


void helpme()
{
	printf( 
			"cmdline opts:\n"
			"-f <file>\tfilename that contains the eeprom dump (default: " DEFAULT_FILE_NAME ")\n"
			"-b <file>\tfilename that contains the raw flash image (default " DEFAULT_FLASH_NAME ")\n"
			"-Y \tincrease \"I know what i'm doing\" value, to enable functionality likely to break the radio\n"
			"-D \twait for the message from the radio flasher, print it's version\n"
			"-F \tflash firmware, WARNING: this will likely brick your radio!\n"
			"-M <ver> \tSet the firmware major version to <ver> during the flash process (default: " DEFAULT_FLASH_VERSION ")\n"
			"-r \tread eeprom\n"
			"-w \twrite eeprom like the original software does\n"
			"-W \twrite most of the eeprom (but without what i think is calibration data)\n"
			"-B \twrite ALL of the eeprom (the \"brick my radio\" mode)\n"
			"-p <port>\tdevice name (default: " DEFAULT_SERIAL_PORT ")\n"
			"-s <speed>\tserial speed (default: 38400, the UV-K5 doesn't accept any other speed)\n"
			"-h \tprint this help\n"
			"-v \tbe verbose, use multiple times for more verbosity\n"

	      );
}


static speed_t baud_to_speed_t(int baud)
{
	switch (baud) {
		case 0:
			return B0;
		case 50:
			return B50;
		case 75:
			return B75;
		case 110:
			return B110;
		case 150:
			return B150;
		case 200:
			return B200;
		case 300:
			return B300;
		case 600:
			return B600;
		case 1200:
			return B1200;
		case 1800:
			return B1800;
		case 2400:
			return B2400;
		case 4800:
			return B4800;
		case 9600:
			return B9600;
		case 19200:
			return B19200;
		case 38400:
			return B38400;
		case 57600:
			return B57600;
		case 115200:
			return B115200;
		default:
			return B0;
	}


}

void parse_cmdline(int argc, char **argv)
{
	int opt;

	/* cmdline opts:
	 * -f <file>
	 * -b <flash file>
	 * -F (flash firmware)
	 * -r (read)
	 * -w (write)
	 * -p <port>
	 * -s <speed>
	 * -h (help)
	 * -v (verbose)
	 * -D (flashdebug)
	 * -F (flash)
	 * -Y (i know what i'm doing)
	 */

	while ((opt=getopt(argc,argv,"f:rwWBp:s:hvDFYb:M:"))!=EOF)
	{
		switch (opt)
		{
			case 'h':
				helpme();
				exit(0);
				break;
			case 'v':
				verbose++;
				break;
			case 'Y':
				i_know_what_im_doing++;
				break;
			case 'r':
				mode=MODE_READ;
				break;
			case 'w':
				mode=MODE_WRITE;
				break;
			case 'D':
				mode=MODE_FLASH_DEBUG;
				break;
			case 'F':
				mode=MODE_FLASH;
				break;
			case 'b':
				flash_file=optarg;
				break;
			case 'M':
				strncpy(flash_version_string,optarg,sizeof(flash_version_string)-1);
				break;
			case 'W':
				mode=MODE_WRITE_MOST;
				break;
			case 'B':
				mode=MODE_WRITE_ALL;
				break;
			case 'f':
				file=optarg;
				break;
			case 'p':
				ser_port=optarg;
				break;
			case 's':

				ser_speed=baud_to_speed_t(atoi(optarg));
				if (ser_speed==B0) {
					fprintf(stderr,"ERROR, unknown speed %s\n",optarg);
					exit(1);
					break;

					default:
					fprintf(stderr,"Unknown command line option %s\n",optarg);
					exit(1);
					break;
				}
		}
	}
	if ((mode==MODE_FLASH)&&(write_offset%UVK5_FLASH_BLOCKSIZE!=0))
	{
		fprintf(stderr,"ERROR: write offset has to be a multiple of %x\n",UVK5_FLASH_BLOCKSIZE);
		exit(1);
	}
	if ((mode==MODE_WRITE)&&(write_offset%UVK5_EEPROM_BLOCKSIZE!=0))
	{
		fprintf(stderr,"ERROR: write offset has to be a multiple of %x\n",UVK5_EEPROM_BLOCKSIZE);
		exit(1);
	}
}

int write_file(char *name, unsigned char *buffer, int len)
{
	int fd;
	int l;

	fd=open(name,O_WRONLY|O_CREAT|O_TRUNC,0600);
	if (fd<0) {
		printf("open %s error %d %s\n", name,errno, strerror(errno));
		return(-1);
	}

	l=write(fd,buffer,len);

	if (l!=len) {
		printf("short write (%i) error %d %s\n", l,errno, strerror(errno));
		return(-1);
	}

	close(fd);
	return(1);
}
int k5_prepare(int fd) {
	int r;
	struct k5_command *cmd;

	r=k5_send_buf(fd,uvk5_hello,sizeof(uvk5_hello));
	if (!r) return(0);
	cmd=k5_receive(fd,10000);
	if (!cmd) return(0);

	printf("******  Connected to firmware version: [%s]\n",(cmd->cmd)+4);
	destroy_k5_struct(cmd);

	return(1);
}

int main(int argc,char **argv)
{
	int fd,ffd;
	unsigned char eeprom[UVK5_EEPROM_SIZE];
	unsigned char flash[UVK5_MAX_FLASH_SIZE];
	int flash_length;
	int flash_max_addr;
	int flash_max_block_addr;
	int i,r,j,len;

	printf (VERSION "\n\n"); 

	parse_cmdline(argc,argv);

	if (mode==MODE_NONE) {
		fprintf(stderr,"No operating mode selected, use -w or -r\n");
		helpme();
		exit(1);
	}


	fd=openport(ser_port,ser_speed);

	if (fd<0) {
		fprintf(stderr,"Open %s failed\n",ser_port);
		exit(1);
	}

	if (i_know_what_im_doing) {
		printf("\"I know what i'm doing\" value set to %i\n",i_know_what_im_doing);
	}



	/* flash mode */
	switch(mode)
	{

		case MODE_FLASH_DEBUG:
			if (i_know_what_im_doing<1) {
				printf("ERROR: the \"I know what i'm doing\" value has to be at least 1 to confirm that you know what you're doing\n");
				exit(0);
			}
			wait_flash_message(fd,10000);
			exit(0);
			break;

		case MODE_FLASH:
			if (i_know_what_im_doing<3) {
				printf("ERROR: the \"I know what i'm doing\" value has to be at least 3, to confirm that you really know what you're doing\n");
				exit(0);
			}

			ffd=open(flash_file,O_RDONLY);
			if (ffd<0) {
				fprintf(stderr,"open %s error %d %s\n", file, errno, strerror(errno));
				exit(1);
			}
			flash_length=read(ffd,(unsigned char *)&flash,UVK5_MAX_FLASH_SIZE);
			close(ffd);

			/* arbitrary limit do that someone doesn't flash some random short file */
			if ((i_know_what_im_doing<5)&&(flash_length<50000)) {
				fprintf(stderr,"Failed to read whole eeprom from file %s (read %i), file too short or some other error\n",file,flash_length);
				if (flash_length>0) {
					fprintf(stderr,"This failsafe is here so that people don't mistake config files with flash.\nIt can be ignored with an 'i know what i'm doing' value of at least 5\n");
				}
				exit(1);
			}
			if (verbose>0) { printf ("Read file %s success\n",flash_file); }
			flash_max_addr=flash_length;

			if (write_length>0)  flash_max_addr=write_offset+write_length;
			if (flash_max_addr>flash_length) flash_max_addr=flash_length;

			if (flash_max_addr&0xff) {
				flash_max_block_addr=(flash_max_addr&0xff00)+UVK5_FLASH_BLOCKSIZE;
			} else {
				flash_max_block_addr=(flash_max_addr&0xff00);
			}

			printf("Writing blocks from address 0x%x until 0x%x, firmware size is 0x%x\n",write_offset,flash_max_block_addr,flash_length);


			if (flash_max_block_addr>UVK5_MAX_FLASH_SIZE)  {
				fprintf(stderr,"flash length 0x%x is greater than max flash size 0x%x\n",flash_max_block_addr,UVK5_MAX_FLASH_SIZE);
				exit(1);
			}

			r=wait_flash_message(fd,10000);
			if (!r) exit(0);

			k5_send_flash_version_message(fd,flash_version_string);

			for(i=write_offset; i<flash_max_addr; i+=UVK5_FLASH_BLOCKSIZE)
			{
				len=flash_max_addr-i;
				if (len>UVK5_FLASH_BLOCKSIZE) len=UVK5_FLASH_BLOCKSIZE;

				r=k5_writeflash(fd, (unsigned char *)&flash+i,len,i,flash_max_block_addr);

				printf("*** FLASH at 0x%4.4x length 0x%4.4x  result=%i\n",i,len,r);
				if (!r) {
					printf("Stopping flash due to ERROR!!!\n");
					break;
				}
			}
			exit(0);

	}



	for (i=0;i<UVK5_PREPARE_TRIES;i++)
	{
		if (verbose>0) { printf("k5_prepare: try %i\n",i); }
		r=k5_prepare(fd);
		if (r) break;
	}

	if (!r)
	{
		fprintf(stderr,"Failed to init radio\n");
		exit(1);
	}

	switch(mode)
	{


		case MODE_READ:

			for(i=0;i<UVK5_EEPROM_SIZE; i=i+UVK5_EEPROM_BLOCKSIZE) {
				if (!k5_readmem(fd,(unsigned char *)&eeprom[i],UVK5_EEPROM_BLOCKSIZE,i))
				{
					fprintf(stderr,"Failed to read block 0x%4.4X\n",i);
					exit(1);
				}
				if (verbose>0) { 
					printf("\rread block 0x%4.4X  %i%%",i,(100*i/UVK5_EEPROM_SIZE)); 
					fflush(stdout); 
				}
			}
			close(fd);
			if (verbose>0) { printf("\rSucessfuly read eeprom\n"); }
			if (verbose>2) { hdump((unsigned char *)&eeprom,UVK5_EEPROM_SIZE); }

			write_file(file,(unsigned char *)&eeprom,UVK5_EEPROM_SIZE);

			break;

		case MODE_WRITE:
		case MODE_WRITE_MOST:
		case MODE_WRITE_ALL:
			if ((mode==MODE_WRITE_ALL)&&(i_know_what_im_doing<1)) {
				printf("ERROR: the \"I know what i'm doing\" value has to be at least 1 to confirm that you know what you're doing\n");
				exit(0);
			}

			/* read file */
			ffd=open(file,O_RDONLY);
			if (ffd<0) {
				fprintf(stderr,"open %s error %d %s\n", file, errno, strerror(errno));
				exit(1);
			}
			r=read(ffd,(unsigned char *)&eeprom[i],UVK5_EEPROM_SIZE);
			if (r!=UVK5_EEPROM_SIZE) {
				fprintf(stderr,"Failed to read whole eeprom from file %s, file too short?\n",file);
				exit(1);
			}
			close(ffd);
			if (verbose>0) { printf ("Read file %s success\n",file); }
			if ((mode==MODE_WRITE_ALL) || (mode==MODE_WRITE_MOST)) {
				j=UVK5_EEPROM_SIZE_WITHOUT_CALIBRATION;
				if (mode==MODE_WRITE_ALL) j=UVK5_EEPROM_SIZE;

				/* write to radio */
				for(i=0;i<j; i=i+UVK5_EEPROM_BLOCKSIZE) {
					if (!k5_writemem(fd,(unsigned char *)&eeprom[i],UVK5_EEPROM_BLOCKSIZE,i))
					{
						fprintf(stderr,"Failed to write block 0x%4.4X\n",i);
						exit(1);
					}
					if (verbose>0) { 
						printf("\rwrite block 0x%4.4X  %i%%",i,(100*i/j)); 
						fflush(stdout); 
					}

				} 
			} else {
				/* write to radio */

				i=0;
				while (uvk5_writes[i][1]) { i++; }
				j=i;

				i=0;
				while (uvk5_writes[i][1]) {
					if (!k5_writemem(fd,(unsigned char *)&eeprom[uvk5_writes[i][0]],uvk5_writes[i][1],uvk5_writes[i][0]))
					{
						fprintf(stderr,"Failed to write block 0x%4.4X length 0x%2.2x\n",uvk5_writes[i][0],uvk5_writes[i][1]);
						exit(1);
					}
					if (verbose>0) { 
						printf("\rwrite block 0x%4.4X  %i%%",i,(100*i/j)); 
						fflush(stdout); 
					}
					i++;
				}
			}
			k5_reset(fd);
			if (verbose>0) { printf("\rSucessfuly wrote eeprom\n"); }


			break;
		default:
			fprintf(stderr,"this shouldn't happen :)\n");
			break;
	}

	return(0); /* silence gcc */
}
