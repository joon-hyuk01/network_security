#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    // destination host address
    u_char  ether_shost[6];    // source host address
    u_short ether_type;        // IP? ARP? RARP? etc
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4,   //IP header length
                       iph_ver:4;    //IP version
    unsigned char      iph_tos;      //Type of service
    unsigned short int iph_len;      //IP Packet length (data + header)
    unsigned short int iph_ident;    //Identification
    unsigned short int iph_flag:3,   //Fragmentation flags
                       iph_offset:13; //Flags offset
    unsigned char      iph_ttl;      //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum;   //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               // source port
    u_short tcp_dport;               // destination port
    u_int   tcp_seq;                 // sequence number
    u_int   tcp_ack;                 // acknowledgement number
    u_char  tcp_offx2;               // data offset, rsvd
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_char  tcp_flags;
    u_short tcp_win;                 // window
    u_short tcp_sum;                 // checksum
    u_short tcp_urp;                 // urgent pointer
};

void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    // 패킷 데이터에서 Ethernet 헤더를 가리키는 포인터 설정
    struct ethheader *eth = (struct ethheader *)packet;

    // 패킷 데이터에서 IP 헤더를 가리키는 포인터 설정
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    
    // IP 헤더의 길이 계산 (4바이트 단위로 표현되는 길이 필드를 바이트 단위로 변환)
    int ip_header_length = ip->iph_ihl * 4;

    // 패킷 데이터에서 TCP 헤더를 가리키는 포인터 설정
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_length);

    // Ethernet 정보 출력
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

    // IP 정보 출력
    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    // TCP 포트 정보 출력
    printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

    // TCP 메시지 출력 (첫 8바이트만 출력)
    printf("Message: ");
    int message_len = ntohs(ip->iph_len) - ip_header_length - (tcp->tcp_offx2 >> 4) * 4;
    int print_len = message_len > 8 ? 8 : message_len;
    for (int i = 0; i < print_len; i++) {
        printf("%02x ", packet[ip_header_length + (tcp->tcp_offx2 >> 2) + i]);
    }

    printf("\n\n");
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 지정된 네트워크 인터페이스로부터 패킷을 캡처하기 위한 세션 열기
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // 패킷 캡처 루프 실행
    pcap_loop(handle, 0, packet_capture, NULL);

    // 패킷 캡처 세션 닫기
    pcap_close(handle);

    return 0;
}
