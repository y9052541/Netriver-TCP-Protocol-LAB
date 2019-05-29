/*
* THIS FILE IS FOR TCP TEST
*/

/*
struct sockaddr_in {
short   sin_family;
u_short sin_port;
struct  in_addr sin_addr;
char    sin_zero[8];
};
*/

#include "sysInclude.h"
#include <cstdio>
#include <cstring>
#include <vector>


int gSrcPort = 2005;
int gDstPort = 2006;
int gSeqNum = 1;
int gAckNum = 1;

struct TCPHead {
	uint16_t srcPort;
	uint16_t dstPort;
	uint32_t seqNum;
	uint32_t ackNum;
	uint8_t headLen;
	uint8_t flag;
	uint16_t windowSize;
	uint16_t checkSum;
	uint16_t urgentPointer;
	char data[105];
	void ntoh() {
		srcPort = ntohs(srcPort);
		dstPort = ntohs(dstPort);
		seqNum = ntohl(seqNum);
		ackNum = ntohl(ackNum);
		windowSize = ntohs(windowSize);
		checkSum = ntohs(checkSum);
		urgentPointer = ntohs(urgentPointer);
	}
	void display() {
		printf("++++++++++++ tcp_head display -----------\n");
		printf("srcPort dstPort (%d, %d)\n", srcPort, dstPort);
		printf("seqNum ackNum (%d, %d)\n", seqNum, ackNum);
		printf("headLen flag (%d, %d)\n", headLen, flag);
		printf("windowSize, checkSum, urgentPointer (%d, %d, %d)\n", windowSize, checkSum, urgentPointer);
		printf("------------ endof -----------\n");
	}
};

struct TCBStruct {
	unsigned int srcAddr;
	unsigned int dstAddr;
	unsigned short srcPort;
	unsigned short dstPort;

	unsigned int seq;
	unsigned int ack;
	unsigned int ackExpect;
	int sockfd;

	BYTE status;

	unsigned char* data;

	void display() {
		printf("~~~~~~~~ TCB TCB display -----------\n");
		printf("srcAddr dstAddr (%d, %d)\n", srcAddr, dstAddr);
		printf("srcPort dstPort (%d, %d)\n", srcPort, dstPort);
		printf("seq ack (%d, %d)\n", seq, ack);
		printf("~~~~~~~~ endof -----------\n");
	}
};
vector<TCBStruct*> TCBTable;

int TCBNum = 0;
enum status { CLOSED, SYN_SENT, ESTABLISHED, FIN_WAIT1, FIN_WAIT2, TIME_WAIT };

TCBStruct* current_tcb;

extern void tcp_DiscardPkt(char *pBuffer, int type);

extern void tcp_sendReport(int type);

extern void tcp_sendIpPkt(unsigned char *pData, UINT16 len, unsigned int  srcAddr, unsigned int dstAddr, UINT8	ttl);

extern int waitIpPacket(char *pBuffer, int timeout);

extern unsigned int getIpv4Address();

extern unsigned int getServerIpv4Address();

unsigned int get_check_sum(TCPHead* tcp_head, unsigned short len, unsigned int srcAddr, unsigned int dstAddr) {
	unsigned int checkSum = 0;
	checkSum += (srcAddr >> 16) + (srcAddr & 0xFFFF);
	checkSum += (dstAddr >> 16) + (dstAddr & 0xFFFF);
	checkSum += IPPROTO_TCP;
	checkSum += 0x14;

	checkSum += tcp_head->srcPort;
	checkSum += tcp_head->dstPort;
	checkSum += ((tcp_head->seqNum) >> 16) + ((tcp_head->seqNum) & 0xFFFF);
	checkSum += ((tcp_head->ackNum) >> 16) + ((tcp_head->ackNum) & 0xFFFF);
	checkSum += ((tcp_head->headLen) << 8) + (tcp_head->flag);
	checkSum += tcp_head->windowSize;
	checkSum += tcp_head->urgentPointer;

	checkSum += len;
	for (int i = 0; i < len; i += 2) {
		checkSum += ((tcp_head->data[i]) << 8) + (tcp_head->data[i + 1] & 0xFF);
	}

	checkSum = (checkSum >> 16) + (checkSum & 0xFFFF);
	checkSum = (~checkSum) & 0xFFFF;

	return checkSum;
}

int stud_tcp_input(char *pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr)
{
	TCPHead* tcp_head = (TCPHead *)pBuffer;
	tcp_head->ntoh();
	// printf("---------> stud_tcp_input len -> %d, (sockfd, ack, seq) --> (%d, %d, %d)\n", len, current_tcb->sockfd, tcp_head->ackNum, tcp_head->seqNum);
	
	// tcp_head->display();

	if (get_check_sum(tcp_head, len - 0x14, ntohl(srcAddr), ntohl(dstAddr)) != tcp_head->checkSum) {
		// printf("check sum error ----------> %d %d\n", get_check_sum(tcp_head, len - 0x14, ntohl(srcAddr), ntohl(dstAddr)), tcp_head->checkSum);
		return -1;
	}

	if (tcp_head->ackNum != current_tcb->ackExpect) {
		// printf("no no no no no -------------> (head_ackNum, tcb_seqExp, sockfd) --> (%d, %d, %d)\n", tcp_head->ackNum, current_tcb->ackExpect, current_tcb->sockfd);
		tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);
		return -1;
	}

	if (current_tcb->status == SYN_SENT && tcp_head->flag == PACKET_TYPE_SYN_ACK) {
		// printf("SYN_SENT ------------->\n");
		current_tcb->status = ESTABLISHED;
		current_tcb->seq = tcp_head->ackNum;
		current_tcb->ack = tcp_head->seqNum + 1;
		stud_tcp_output(NULL, 0, PACKET_TYPE_ACK,
			current_tcb->srcPort,
			current_tcb->dstPort,
			current_tcb->srcAddr,
			current_tcb->dstAddr);
		return 0;
	}
	if (current_tcb->status == ESTABLISHED) {
		// printf("ESTABLISHED ------------->\n");
		current_tcb->seq = tcp_head->ackNum;
		current_tcb->ack = tcp_head->seqNum + (len - 0x14);
		stud_tcp_output(NULL, 0, PACKET_TYPE_ACK,
			current_tcb->srcPort,
			current_tcb->dstPort,
			current_tcb->srcAddr,
			current_tcb->dstAddr);
		return 0;
	}
	if (current_tcb->status == FIN_WAIT1 && tcp_head->flag == PACKET_TYPE_ACK) {
		// printf("FIN_WAIT1 ------------->\n");
		current_tcb->status = FIN_WAIT2;
		current_tcb->seq = tcp_head->ackNum;
		current_tcb->ack = tcp_head->seqNum + 1;
		return 0;
	}
	if (current_tcb->status == FIN_WAIT2 && tcp_head->flag == PACKET_TYPE_FIN_ACK) {
		// printf("FIN_WAIT2 ------------->\n");
		current_tcb->status = TIME_WAIT;
		stud_tcp_output(NULL, 0, PACKET_TYPE_ACK,
			current_tcb->srcPort,
			current_tcb->dstPort,
			current_tcb->srcAddr,
			current_tcb->dstAddr);
		return 0;
	}

	return -1;
}

void stud_tcp_output(char *pData, unsigned short len, unsigned char flag, unsigned short srcPort, unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr)
{
	// printf("---------> stud_tcp_output --> %d\n", len);
	if (current_tcb == NULL) {
		current_tcb = new TCBStruct;
		current_tcb->ack = gAckNum;
		current_tcb->seq = gSeqNum;
		current_tcb->srcAddr = srcAddr;
		current_tcb->dstAddr = dstAddr;
		current_tcb->srcPort = srcPort;
		current_tcb->dstPort = dstPort;
		current_tcb->status = CLOSED;
	}
	TCPHead* tcp_head = new TCPHead;
	memcpy(tcp_head->data, pData, len);

	tcp_head->srcPort = srcPort;
	tcp_head->dstPort = dstPort;
	tcp_head->seqNum = current_tcb->seq;
	tcp_head->ackNum = current_tcb->ack;
	tcp_head->headLen = 0x50;
	tcp_head->flag = flag;
	tcp_head->windowSize = 1;
	tcp_head->urgentPointer = 0;
	tcp_head->checkSum = get_check_sum(tcp_head, len, srcAddr, dstAddr);
	//tcp_head->display();
	tcp_head->ntoh(); // same as hton()

	if (current_tcb->status == CLOSED && tcp_head->flag == PACKET_TYPE_SYN) {
		// printf("CLOSED ~~~~~~~~~~~~>\n");
		current_tcb->status = SYN_SENT;
	}
	if (current_tcb->status == ESTABLISHED && tcp_head->flag == PACKET_TYPE_FIN_ACK) {
		// printf("ESTABLISHED PACKET_TYPE_FIN_ACK ~~~~~~~~~~~~>\n");
		current_tcb->status = FIN_WAIT1;
	}

	if (current_tcb->status == ESTABLISHED) {
		current_tcb->ackExpect = current_tcb->seq + len;
	}
	else {
		current_tcb->ackExpect = current_tcb->seq + 1;
	}
	// printf("current_tcb ackExpect ~~~~~~~~~~~~> (%d, %d)\n", current_tcb->sockfd, current_tcb->ackExpect);

	tcp_sendIpPkt((unsigned char *)tcp_head, 20 + len, current_tcb->srcAddr, current_tcb->dstAddr, 60);
}

int stud_tcp_socket(int domain, int type, int protocol)
{
	// printf("-------> stud_tcp_socket\n");
	if (TCBNum == 0) {
		TCBTable.push_back(NULL);
		TCBNum++;
	}
	current_tcb = new TCBStruct;
	current_tcb->ack = gAckNum;
	current_tcb->seq = gSeqNum;
	current_tcb->srcPort = gSrcPort++;
	current_tcb->sockfd = TCBNum++;
	current_tcb->status = CLOSED;

	TCBTable.push_back(current_tcb);

	// current_tcb->display();
	// printf("-------> stud_tcp_socket --> sockfd %d\n",current_tcb->sockfd);
	return current_tcb->sockfd;
}

int stud_tcp_connect(int sockfd, struct sockaddr_in *addr, int addrlen)
{
	// printf("-------> stud_tcp_connect\n");
	current_tcb = TCBTable[sockfd];

	current_tcb->dstPort = ntohs(addr->sin_port);
	current_tcb->status = SYN_SENT;
	current_tcb->srcAddr = getIpv4Address();
	current_tcb->dstAddr = htonl(addr->sin_addr.s_addr);

	//current_tcb->display();
	stud_tcp_output(NULL, 0, PACKET_TYPE_SYN,
		current_tcb->srcPort, current_tcb->dstPort,
		current_tcb->srcAddr, current_tcb->dstAddr);

	TCPHead* tcp_head = new TCPHead;
	int len = waitIpPacket((char *)tcp_head, 5000);
	while (len == -1) {
		len = waitIpPacket((char *)tcp_head, 5000);
	}
	return stud_tcp_input((char *)tcp_head, len, ntohl(current_tcb->srcAddr), ntohl(current_tcb->dstAddr));
}

int stud_tcp_send(int sockfd, const unsigned char *pData, unsigned short datalen, int flags)
{
	// printf("****************-> stud_tcp_send\n");
	current_tcb = TCBTable[sockfd];
	//current_tcb->display();

	if (current_tcb->status == ESTABLISHED) {
		current_tcb->data = (unsigned char *) pData;
		stud_tcp_output((char *)current_tcb->data, datalen, PACKET_TYPE_DATA, 
			current_tcb->srcPort, current_tcb->dstPort,
			current_tcb->srcAddr, current_tcb->dstAddr);

		TCPHead* tcp_head = new TCPHead;
		int len = waitIpPacket((char *)tcp_head, 5000);
		while (len == -1) {
			len = waitIpPacket((char *)tcp_head, 5000);
		}
		return stud_tcp_input((char *)tcp_head, len, ntohl(current_tcb->srcAddr), ntohl(current_tcb->dstAddr));
	}
	return -1;
}

int stud_tcp_recv(int sockfd, unsigned char *pData, unsigned short datalen, int flags)
{
	// printf("-------> stud_tcp_recv\n");
	current_tcb = TCBTable[sockfd];

	if (current_tcb->status == ESTABLISHED) {
		TCPHead* tcp_head = new TCPHead;
		int len = waitIpPacket((char *)tcp_head, 5000);
		while (len == -1) {
			len = waitIpPacket((char *)tcp_head, 5000);
		}
		memcpy(pData, tcp_head->data, sizeof(tcp_head->data));
		return stud_tcp_input((char *)tcp_head, len, ntohl(current_tcb->srcAddr), ntohl(current_tcb->dstAddr));
	}
	return -1;
}

int stud_tcp_close(int sockfd)
{
	// printf("-------> stud_tcp_close\n");
	current_tcb = TCBTable[sockfd];

	if (current_tcb->status == ESTABLISHED) {
		stud_tcp_output(NULL, 0, PACKET_TYPE_FIN_ACK,
			current_tcb->srcPort, current_tcb->dstPort,
			current_tcb->srcAddr, current_tcb->dstAddr);

		TCPHead* tcp_head = new TCPHead;
		int len = waitIpPacket((char *)tcp_head, 5000);
		while (len == -1) {
			len = waitIpPacket((char *)tcp_head, 5000);
		}
		stud_tcp_input((char *)tcp_head, len, ntohl(current_tcb->srcAddr), ntohl(current_tcb->dstAddr));

		tcp_head = new TCPHead;
		len = waitIpPacket((char *)tcp_head, 5000);
		while (len == -1) {
			len = waitIpPacket((char *)tcp_head, 5000);
		}
		return stud_tcp_input((char *)tcp_head, len, ntohl(current_tcb->srcAddr), ntohl(current_tcb->dstAddr));
	}
	return -1;
}
