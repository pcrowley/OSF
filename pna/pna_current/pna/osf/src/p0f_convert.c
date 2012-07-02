#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

//Type definitions for fixed-width data (userspace)
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef	int8_t	 s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

struct osf_print{
	//Fingerprint info, 27 bytes
	u8		done;//Flag set to 1 if log is complete, 0 if empty
	u32		src_ip;//Source IP
	u32		dst_ip;//Destination IP
	u16		opt_hash;//Should never exceed 12800
	u32		quirks;//Set of 17 quirk flags.
	u8		opt_eol_pad;//Amount of bytes past EOL, 40 max
	u8		ip_opt_len;//Length of IP options
	u8		ip_version;//0=any, 4=IPv4, 6=IPv6
	u8		ttl;//Time to live
	u16		mss;//Max segment size, max 65535
	u16		win;//Window size, max 65535
	u8		win_type;//Window type, explained below
	u8		win_scale;//Window scaling, max 255
	u8		pay_class;//0 = any, 1 = No data, 2 = data
	u32		ts1;
	u32		ts2;
	u8		wildcards;//Set of wildcards for above values, see below
	u32		unix_time;//If this doesn't work, change to u64?
	char	os_type;
	char	os_class[5];
	char	os_name[20];
	char	os_flavor[20];
//Window type:
/*
	0=Wildcard.  The value for win can be anything.
	1=Direct value.  The value used for win is exact.
	2=Multiple of MSS.  Actual window is = win * mss.
	3=Multiple of MTU.  Actual window is = win * mtu.
	MTU should never come up.
	4=Multiple of a fixed value.  Actual window % win = 0.
*/
//Wildcards:
/*
	A set of flags for the values that can be wildarded,
	organized by bits:
	1=mss
	2=win_scale
*/
};

struct osf_tcp_mat{
	char type;  //g for generic, s for standard
	char os_class[5]; //The general class of OS, such as win, unix, cisco
	char name[20]; //The specific name of OS or app, such as Linux, NMap, etc
	char flavor[20]; //The flavor of OS, such as a version number
};

void gen_tcp_fp(char *buff, struct osf_tcp_mat label, struct osf_print *fp){
	char temp[10];
	char debug[10];
	char *cur;
	int read;
	memset(fp, 0, sizeof(struct osf_print));
	//Copy the label
	//memcpy(&(fp->tcp_mat), &label, sizeof(struct osf_tcp_mat));
	memcpy(&(fp->os_type), &label, sizeof(struct osf_tcp_mat));
	//Begin calculating each tcp_sig field, in the order they appear in buff:
	//First, skip over the first 8 bytes, since they never contain relevant info:
	cur = buff + 8;
	read = 0;
	//Now, we must read one byte to get the ip version:
	memcpy(&temp, cur, 1);
	temp[1] = '\0';
	if(temp[0] == '*'){
		fp->ip_version = 0;
	}
	else{
		fp->ip_version = atoi(temp);
	}
	cur = cur + 2;
	//Next is the initial TTL, this is directly copied;
	while(*(cur+read) != ':'){
		read++;	
	}
	memcpy(&temp, cur, read);
	temp[read] = '\0';
	fp->ttl = atoi(temp);
	cur = cur + read + 1;
	read = 0;
	//IP option length is next, also directly copied:
	while(*(cur+read) != ':'){
		read++;	
	}
	memcpy(&temp, cur, read);
	temp[read] = '\0';
	fp->ip_opt_len = atoi(temp);
	cur = cur + read + 1;
	read = 0;
	//Next is MSS, copied directly, unless there's a wildcard,
	while(*(cur+read) != ':'){
		read++;	
	}
	memcpy(&temp, cur, read);
	temp[read] = '\0';
	if(temp[0] == '*'){
		fp->mss = 0;
		fp->wildcards = fp->wildcards | 1;	
	}
	else{
		fp->mss = atoi(temp);
	}
	cur = cur + read + 1;
	read = 0;
	//Next is window size, this one takes some work.
	//The window size inside of pna_osf.c is recorded exactly as it appears
	//in the TCP window field.  Here, we record one of four possibilities.
	//I'm using the win_type to show what kind of window we're dealing with
	//0=Wildcard
	//1=Fixed value, win is static
	//2=MSS multiple, win is multiple of MSS
	//3=MTU multiple, no way to calculate this, but it can still be recorded
	//4=Multiple of integer, win is multiple of some value
	//First, let's determine the case:
	memcpy(&temp, cur, 1);
	temp[1] = '\0';
	if (temp[0] == '*'){
		fp->win_type = 0;
		fp->win = 0;
		cur = cur + 2;
		read = 0;	
	}
	else if(temp[0] == 'm'){
		if(*(cur+1) == 's'){
			fp->win_type = 2;
		}	
		else if(*(cur+1) == 't'){
			fp->win_type = 3;
		}
		else{
			fp->win_type = 0;
		}
		cur = cur + 4;
		read = 0;
		while(*(cur+read) != ','){
			read++;		
		}
		memcpy(&temp, cur, read);
		temp[read] = '\0';
		fp->win = atoi(temp);
		cur = cur + read + 1;
	}
	else if(temp[0] == '%'){
		fp->win_type = 4;
		cur = cur + 1;
		read = 0;
		while(*(cur+read) != ','){
			read++;		
		}
		memcpy(&temp, cur, read);
		temp[read] = '\0';
		fp->win = atoi(temp);
		cur = cur+read + 1;
	}
	else{
		fp->win_type = 1;
		read = 0;
		while(*(cur+read) != ','){
			read++;
		}
		memcpy(&temp, cur, read);
		temp[read] = '\0';
		fp->win = atoi(temp);
		cur = cur + read + 1;
	}
	read = 0;
	//Now getting the window scale, normal copy
	while(*(cur+read) != ':'){
		read++;	
	}
	memcpy(&temp, cur, read);
	temp[read] = '\0';
	if(temp[0] == '*'){
		fp->win_scale = 0;
		fp->wildcards = fp->wildcards | 2;
	}
	else{
		fp->win_scale = atoi(temp);
	}
	cur = cur + read + 1;
	read = 0;
	//Now we have to read in the options and calculate the opt_hash
	//and a few other things:
	int opt_num = 0;
	while(*(cur) != ':'){
		opt_num++;
		if(*cur == 'e'){
			cur = cur + 4;
			while(*(cur+read) != ':'){
				read++;			
			}
			memcpy(&temp, cur, read);
			temp[read] = '\0';
			fp->opt_eol_pad = atoi(temp);
			cur = cur + read; //We don't read past the : this time.
			read = 0;
			continue;
		}
		//Experimental Hash Improvement
		else if(*cur == 'n'){
			memcpy(&temp, cur, 3);
			temp[3] = '\0';
			fp->opt_hash = fp->opt_hash * 8;
			fp->opt_hash = fp->opt_hash + (1 + opt_num) * opt_num;
			cur = cur + 3;
			read = 0;
			continue;	
		}
		else if(*cur == 'm'){
			memcpy(&temp, cur, 3);
			temp[3] = '\0';
			fp->opt_hash = fp->opt_hash * 8;
			fp->opt_hash = fp->opt_hash + (2 + opt_num) * opt_num;
			cur = cur + 3;
			read = 0;
			continue;
		}
		else if(*cur == 'w'){
			memcpy(&temp, cur, 2);
			temp[2] = '\0';
			fp->opt_hash = fp->opt_hash * 8;
			fp->opt_hash = fp->opt_hash + (3 + opt_num) * opt_num;
			cur = cur + 2;
			read = 0;
			continue;
		}
		else if(*cur == 's' && *(cur+1) == 'o'){
			memcpy(&temp, cur, 3);
			temp[3] = '\0';
			fp->opt_hash = fp->opt_hash * 8;
			fp->opt_hash = fp->opt_hash + (4 + opt_num) * opt_num;
			cur = cur + 3;
			read = 0;
			continue;
		}
		else if(*cur == 's' && *(cur+1) == 'a'){
			memcpy(&temp, cur, 4);
			temp[4] = '\0';
			fp->opt_hash = fp->opt_hash * 8;
			fp->opt_hash = fp->opt_hash + (5 + opt_num) * opt_num;
			cur = cur + 4;
			read = 0;
			continue;
		}
		else if(*cur == 't'){
			memcpy(&temp, cur, 2);
			temp[2] = '\0';
			fp->opt_hash = fp->opt_hash * 8;
			fp->opt_hash = fp->opt_hash + (8 + opt_num) * opt_num;
			cur = cur + 2;
			read = 0;
			continue;		
		}
		else{
			opt_num--;
			cur = cur + 1;
			read = 0;
			continue;
		}
	}
	cur = cur + 1;
	read = 0;
	//Now, to get the quirks list
	unsigned int quirks = 0;
	while(*cur != ':'){
		if(*cur == 'd'){
			quirks = quirks + (1 << 0);
			cur = cur + 2;
			continue;	
		}
		else if(*cur == 'i' && *(cur + 2) == '+'){
			quirks = quirks + (1 << 1);
			cur = cur + 3;
			continue;		
		}
		else if(*cur == 'i' && *(cur + 2) == '-'){
			quirks = quirks + (1 << 2);
			cur = cur + 3;
			continue;
		}
		else if(*cur == 'e' && *(cur + 1) == 'c'){
			quirks = quirks + (1 << 3);
			cur = cur + 3;
			continue;
		}
		else if(*cur == '0'){
			quirks = quirks + (1 << 4);
			cur = cur + 2;
			continue;
		}
		else if(*cur == 'f'){
			quirks = quirks + (1 << 5);
			cur = cur + 4;
			continue;
		}
		else if(*cur == 's'){
			quirks = quirks + (1 << 6);
			cur = cur + 4;
			continue;
		}
		else if(*cur == 'a' && *(cur + 3) == '+'){
			quirks = quirks + (1 << 7);
			cur = cur + 4;
			continue;
		}
		else if(*cur == 'a' && *(cur + 3) == '-'){
			quirks = quirks + (1 << 8);
			cur = cur + 4;
			continue;
		}
		else if(*cur == 'u' && *(cur + 1) == 'p'){
			quirks = quirks + (1 << 9);
			cur = cur + 5;
			continue;
		}
		else if(*cur == 'u' && *(cur + 1) == 'r'){
			quirks = quirks + (1 << 10);
			cur = cur + 5;
			continue;
		}
		else if(*cur == 'p'){
			quirks = quirks + (1 << 11);
			cur = cur + 6;
			continue;
		}
		else if(*cur == 't' && *(cur+3) == '-'){
			quirks = quirks + (1 << 12);
			cur = cur + 4;
			continue;
		}
		else if(*cur == 't' && *(cur+3) == '+'){
			quirks = quirks + (1 << 13);
			cur = cur + 4;
			continue;
		}
		else if(*cur == 'o'){
			quirks = quirks + (1 << 14);
			cur = cur + 4;
			continue;
		}
		else if(*cur == 'e' && *(cur+1) == 'x'){
			quirks = quirks + (1 << 15);
			cur = cur + 4;
			continue;
		}
		else if(*cur == 'b'){
			quirks = quirks + (1 << 16);
			cur = cur + 3;
			continue;
		}
		else{
			cur = cur + 1;
			continue;
		}
	}
	cur = cur + 1;
	read = 0;
	fp->quirks = quirks;
	//Now, for the payload class.
	if(*cur == '*'){
		fp->pay_class = 0;
	}
	else if(*cur == '0'){
		fp->pay_class = 1;
	}
	else{
		fp->pay_class = 2;
	}
	return;
}

void gen_tcp_label(char *buff, struct osf_tcp_mat *label){
	char *cur = buff + 8;
	int read = 0;
	memset(label, 0, sizeof(struct osf_tcp_mat));
	label->type = *cur;
	cur = cur + 2;
	while(*(cur+read) != ':'){
		read++;	
	}
	memcpy(&(label->os_class), cur, read);
	label->os_class[read] = '\0';
	cur = cur + read + 1;
	read = 0;

	while(*(cur+read) != ':'){
		read++;	
	}
	memcpy(&(label->name), cur, read);
	label->name[read] = '\0';
	cur = cur + read + 1;
	read = 0;

	while(*(cur+read) != '\n'){
		read++;	
	}

	memcpy(&(label->flavor), cur, read);
	label->flavor[read] = '\0';
	if(label->flavor[read-1] == '\n'){
		label->flavor[read-1] = '\0';	
	}
	cur = cur + read + 1;
	read = 0;
	return;
}
/*
struct osf_tcp_sig{
	unsigned int opt_hash;//A hash of the option layout.
	unsigned int quirks;//TCP quirks, as defined in p0f
	unsigned short opt_eol_pad;//Amount of padding past EOL
	unsigned short ip_opt_len;//Length of IP options
	short ip_ver;//-1 = any, other values indicate IPv4 and IPv6
	unsigned short ttl; //Original TTL, calculated using p0f's function
	unsigned int mss; //MSS -1 is wild
	unsigned int win; //Window size
	unsigned short win_type; //Window Type
	int win_scale; //Window scale -1 = any
	short pay_class; //-1 = any 0 = zero  1 = non-zero
	unsigned int tot_hdr; //Total header length
	unsigned int ts1; //Own timestamp
	unsigned int recv_ms; //Pack recv unix time (ms)
};

struct osf_tcp_mat{
	char type;  //g for generic, s for standard
	char os_class[5]; //The general class of OS, such as win, unix, cisco
	char name[20]; //The specific name of OS or app, such as Linux, NMap, etc
	char flavor[20]; //The flavor of OS, such as a version number
};
struct osfmon_entry {
    unsigned int	local_ip;
	struct osf_tcp_sig tcp_sig;
	struct osf_tcp_mat tcp_mat;
};
*/
void output_fp(struct osf_print *fp){
	printf("OS Type: %c\n", fp->os_type);
	printf("OS Class: %s\n", fp->os_class);
	printf("OS Name: %s\n", fp->os_name);
	printf("OS Flavor: %s", fp->os_flavor);
	printf("opt_hash: %u\n", fp->opt_hash);
	printf("quirks: %u\n", fp->quirks);
	printf("opt_eol_pad: %u\n", fp->opt_eol_pad);
	printf("ip_opt_len: %u\n", fp->ip_opt_len);
	printf("ip_ver: %d\n", fp->ip_version);
	printf("ttl: %u\n", fp->ttl);
	printf("mss: %u\n", fp->mss);
	printf("win: %u\n", fp->win);
	printf("win_type: %u\n", fp->win_type);
	printf("win_scale: %d\n", fp->win_scale);
	printf("pay_class: %d\n", fp->pay_class);
	printf("\n");
}
int main(int argc, char* argv[])
{
	if (argc != 2){
		printf("Incorrect number of arguements\n");
		return 1;
	}
	char *filename = argv[1];
	FILE *ifp;
	FILE *ofpm;
	FILE *ofpt;
	FILE *ofph;
	FILE *ofpg;
	ifp = fopen(filename, "r");
	ofpm = fopen("mtu.osf", "w");
	ofpt = fopen("tcp.osf", "w");
	ofph = fopen("http.osf", "w");
	ofpg = fopen("garbage.osf", "w");
	if (ifp == NULL || ofpm == NULL || ofpt == NULL || ofph == NULL || ofpg == NULL){
		printf("File I/O error\n");
		return 1;
	}
	char buff[256];
	struct osf_print tcp_buff;
	int linecount = 0;
	int mode = 0;
	int othercount = 1;
	struct osf_tcp_mat cur_label;
	while (!feof(ifp)){
		fgets(buff, 256, ifp);
		if(buff[0] == ';' || buff[0] == '\n'){
			continue;		
		}
		if(buff[0] == '['){
			if(buff[1] == 'm'){
				mode = 1;				
			}
			else if(buff[1] == 't'){
				if(buff[7] == 'q'){
					mode = 2;
				}
				if(buff[7] == 's'){
					mode = 4;
				}
			}
			else if(buff[1] == 'h'){
				mode = 3;			
			}
			else{
				mode = 0;
			}
		}
		switch(mode){
			case 1:
			fputs(buff, ofpm);
			break;
			case 2:
			if(buff[0] == 'l'){
				gen_tcp_label(buff, &cur_label);
			}
			else if(buff[0] == 's' && buff[1] == 'i'){
				gen_tcp_fp(buff, cur_label, &tcp_buff);
				output_fp(&tcp_buff);
				fwrite(&tcp_buff, sizeof(struct osf_print), 1, ofpt);
			}
			break;
			case 3:
			fputs(buff, ofph);
			break;
			case 4:
			if(buff[0] == 'l'){
				gen_tcp_label(buff, &cur_label);
			}
			else if(buff[0] == 's' && buff[1] == 'i'){
				gen_tcp_fp(buff, cur_label, &tcp_buff);
				tcp_buff.unix_time = 1;
				output_fp(&tcp_buff);
				fwrite(&tcp_buff, sizeof(struct osf_print), 1, ofpt);
			}
			break;
			default:
			fputs(buff, ofpg);
			break;
		}
		linecount++;
	}
	fclose(ifp);
	fclose(ofpm);
	fclose(ofpt);
	fclose(ofph);
	fclose(ofpg);
	return 0;
}
