#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "datatype.h"

UINT32  m_datalen = 56;
UINT16 getChksum(UINT16 *addr, INT32 len)
{   
	INT32 nleft=len;
	INT32 sum=0;
	UINT16 *w=addr;
	UINT16 answer=0;

	/*把ICMP报头二进制数据以2字节为单位累加起来*/
	while(nleft>1)
	{   
		sum+=*w++;
		nleft-=2;
	}
	/*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加*/
	if( nleft==1)
	{   
		*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum+=answer;
	}
	sum=(sum>>16)+(sum&0xffff);
	sum+=(sum>>16);
	answer=~sum;
	return answer;
}
INT32  Icmp_pack(UINT8 *u8Ptr, UINT32 u32Pid, struct timeval *stTvSend, UINT32 u32Seq)
{
    struct icmp *pIcmpInfo = NULL;
    struct timeval *pStTv = NULL;
    INT32   s32PackSize = 0;

    pIcmpInfo = (struct icmp*)u8Ptr;

	pIcmpInfo->icmp_type=ICMP_ECHO;
	pIcmpInfo->icmp_code=0;
	pIcmpInfo->icmp_cksum=0;
	pIcmpInfo->icmp_seq=u32Seq;
	pIcmpInfo->icmp_id= u32Pid;
	
    s32PackSize = 8 + m_datalen;

    pStTv = (struct timeval *)pIcmpInfo->icmp_data;
    *pStTv = *stTvSend;
    //gettimeofday(pStTv, NULL);
    pIcmpInfo->icmp_cksum = getChksum((unsigned short *)pIcmpInfo,s32PackSize); /*校验算法*/

    return s32PackSize;
}
INT32   TimeDIff(struct timeval *tvSend, struct timeval *tvRecv)
{
    INT32 s32TvDif = 0;

    if(!(tvSend && tvRecv))
    {
        return ERROR;
    }

    if(tvSend->tv_sec > tvRecv->tv_sec)
    {
        printf("%s Wrong time recv and send!\n", __func__);
        return ERROR;
    }
    else if(tvSend->tv_sec == tvRecv->tv_sec)
    {
        s32TvDif = (tvRecv->tv_usec - tvSend->tv_usec);
    }
    else
    {
        s32TvDif =( (tvRecv->tv_usec > tvSend->tv_usec ? ((tvRecv->tv_usec - tvSend->tv_usec) + (tvRecv->tv_sec - tvSend->tv_sec) * 1000*1000) :\
           ((tvRecv->tv_usec - tvSend->tv_usec + 1000*1000) + (tvRecv->tv_sec - tvSend->tv_sec - 1) * 1000*1000) ));
    }

    return s32TvDif;
}
INT32   Icmp_unPack(UINT8 *u8Ptr, INT32 s32Len, struct icmp *stRecvIcmp)
{
    INT32 s32Iphdrlen = 0;
    struct ip *stIp = NULL;
    struct icmp *stIcmp = NULL;
    struct timeval *stTvSend = NULL, tvRecv;

    if(stRecvIcmp == NULL)
    {
        printf("%s Wrong params !\n", __func__);
        return ERROR;
    }
    
    stIcmp = stRecvIcmp;
    stIp = (struct ip *)u8Ptr;
    s32Iphdrlen = stIp->ip_hl << 2;
    stIcmp = (struct icmp*)(u8Ptr + s32Iphdrlen);

    memcpy(stRecvIcmp, stIcmp, sizeof(struct icmp));

    return ERROR;
}

INT32 RecvIcmpReply(INT32 s32SktFd, struct sockaddr_in stDstAddr, struct icmp *stRecvIcmp)
{
    struct timeval stTimeout;
    INT32 s32Ret = ERROR;
    fd_set rset;
    UINT8   recvBuf[1024];
    INT32 s32RecvLen;
    socklen_t fromlen = sizeof(struct sockaddr_in);

    memset(&stTimeout, 0,sizeof(struct timeval));
    stTimeout.tv_sec = 2;
    stTimeout.tv_usec = 0;
    
    FD_ZERO(&rset);
    FD_SET(s32SktFd, &rset);
    s32Ret = select(s32SktFd + 1, &rset, NULL, NULL, &stTimeout);    
    if(s32Ret <= 0)
    {
        printf("%s select timeout or failed errno:%d, %s\n", __func__, errno, strerror(errno));
        return ERROR;
    }
    if(FD_ISSET(s32SktFd, &rset))
    {
        s32RecvLen = recvfrom(s32SktFd, recvBuf, 1024, 0,(struct sockaddr *)&stDstAddr,&fromlen);
        if(s32RecvLen <= 0)
        {
            printf("%s recv data length %d, errno %d, %s\n", __func__, s32RecvLen, errno, strerror(errno));
            return ERROR;
        }
        printf("Recv from dst length %d\n", s32RecvLen);

        Icmp_unPack(recvBuf, s32RecvLen, stRecvIcmp);
    }

    return OK;
}

UINT32 Brd_PingIcmp(void *pIpPtr)
{
    struct protoent *protocol;
    struct sockaddr_in  stDstAddr;
    INT32   s32SktFd = ERROR;
    INT32   s32BufSize = 1024;
    UINT8   u8IcmpPack[s32BufSize];
    UINT32  u32IcmpPackSize = 0;
    INT32   s32Ret = ERROR;
    UINT32  u32Pid = 0;    
    struct timeval tvSend, tvRecv;
    UINT32  u32Seq = 0;
    struct  icmp     stRecvIcmp;
    
    protocol = getprotobyname("icmp");
    if(!protocol)
    {
        printf("Get icmp protocal error!");
        return ERROR;
    }

    s32SktFd = socket(AF_INET, SOCK_RAW, protocol->p_proto);
    if(s32SktFd < 0)
    {
        printf("Cannot create socket , error %d|%s\n", errno, strerror(errno));
        return ERROR;
    }

    setsockopt(s32SktFd, SOL_SOCKET, SO_RCVBUF,&s32BufSize,sizeof(s32BufSize));

    memset(&stDstAddr, 0, sizeof(stDstAddr));

    if(0 == inet_aton(pIpPtr, &stDstAddr.sin_addr))
    {
        printf("Cannot convert ipptr %s to dst sockaddr_in!\n", pIpPtr);
        return ERROR;
    }
    //pack icmp info
    u32Pid = getpid();

    gettimeofday(&tvSend, NULL);
    u32IcmpPackSize = Icmp_pack(u8IcmpPack, u32Pid, &tvSend, u32Seq);

  //  send pack
    if((s32Ret = sendto(s32SktFd, u8IcmpPack, u32IcmpPackSize, 0, (struct sockaddr *)&stDstAddr, sizeof(stDstAddr))) < 0)
    {
        printf("Cannot send to dst errno %d %s\n", errno, strerror(errno));
        return ERROR;
    }

    printf("Send to dst %s ok!\n", pIpPtr);

    //recv packet
    memset(&stRecvIcmp, 0, sizeof(struct icmp));
    RecvIcmpReply(s32SktFd, stDstAddr, &stRecvIcmp);

    if(stRecvIcmp.icmp_type == ICMP_ECHOREPLY && (stRecvIcmp.icmp_id == getpid()))
    {
        printf("Get Relpy from dst ：");
        printf("local pid : %d, reply pid : %d\n", getpid(), stRecvIcmp.icmp_id);
        printf("Get Seq id : %d\n", stRecvIcmp.icmp_seq);
        tvSend = *(struct timeval *)stRecvIcmp.icmp_data;
        gettimeofday(&tvRecv, NULL);
        printf("time diff is %d us\n", TimeDIff(&tvSend, &tvRecv) );
    }

    close(s32SktFd);

}

int main(int argc, char *argv[])
{
    UINT8   u8IpAddr;

    if(argc <= 1)
    {
        printf("Wrong params!\n");
        return ERROR;
    }

    Brd_PingIcmp(argv[1]);
    Brd_PingIcmp(argv[1]);
    Brd_PingIcmp(argv[1]);

    return OK;
}
