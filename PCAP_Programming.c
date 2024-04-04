#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
// Ethernet 헤더 구조체 정의
struct ethheader {
 u_char  ether_dhost[6]; // 대상 호스트 주소 
 u_char  ether_shost[6]; // 소스 호스트 주소 
 u_short ether_type;     // 프로토콜 유형 (IP, ARP, RARP 등) 
};
// IP 헤더 구조체 정의 
struct ipheader {
unsigned char      iph_ihl:4, // IP 헤더 길이
                    iph_ver:4; // IP 버전
unsigned char      iph_tos;   // 서비스 유형
unsigned short int iph_len;   // IP 패킷 길이 (데이터 + 헤더)
unsigned short int iph_ident; // 식별자
unsigned short int iph_flag:3,// 단편 플래그
                    iph_offset:13; // 단편 오프셋
unsigned char      iph_ttl;   // TTL
unsigned char      iph_protocol; // 프로토콜 유형
unsigned short int iph_chksum; // IP 데이터그램 체크섬
struct  in_addr    iph_sourceip; // 소스 IP 주소
struct  in_addr    iph_destip;   // 대상 IP 주소
};
// TCP 헤더 구조체 정의 
struct tcpheader {
unsigned short int tcp_sport; // 소스 포트
unsigned short int tcp_dport; // 대상 포트
unsigned int       tcp_seq;   // 시퀀스 번호
unsigned int       tcp_ack;   // 확인 응답 번호
unsigned char      tcp_reserved:4, // 예약 공간 4비트
                    tcp_offset:4;    // TCP 데이터 오프셋 (리틀 엔디안)
unsigned char      tcp_flags;      // TCP 플래그 (및 예약 공간 2비트)
unsigned short int tcp_window;     // TCP 윈도우 크기
unsigned short int tcp_checksum;   // TCP 체크섬
unsigned short int tcp_urgentptr;  // TCP 긴급 포인터
};
// 캡처된 패킷을 처리하는 함수 
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                             const u_char *packet)
{
// Ethernet 헤더 추출
struct ethheader *eth = (struct ethheader *)packet;
// IP 패킷인지 확인
if (ntohs(eth->ether_type) ==0x0800) { // 0x0800은 IP 유형
   // IP 헤더 추출
   struct ipheader *ip = (struct ipheader *)(packet +sizeof(struct ethheader));
   // 프로토콜이 TCP인지 확인
   if (ip->iph_protocol == IPPROTO_TCP) {
     // TCP 헤더 추출
     struct tcpheader *tcp = (struct tcpheader *)(packet +sizeof(struct ethheader) + (ip->iph_ihl *4));
     // Ethernet 헤더 정보 출력
     printf("Ethernet Header:\n");
     printf("   Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
     printf("   Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
     // IP 헤더 정보 출력
     printf("IP Header:\n");
     printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
     printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
     // TCP 헤더 정보 출력
     printf("TCP Header:\n");
     printf("   Source Port: %d\n", ntohs(tcp->tcp_sport));
     printf("   Destination Port: %d\n", ntohs(tcp->tcp_dport));
     // TCP 메시지의 일부 출력
     printf("Message:\n");
     int data_len = ntohs(ip->iph_len) - (ip->iph_ihl *4) - (tcp->tcp_offset *4);
     int max_data_len = data_len <20 ? data_len : 20; // 최대 10바이트까지 데이터 출력
     printf("   ");
     for (int i =0; i < max_data_len; ++i) {
       printf("%02x ", packet[sizeof(struct ethheader) + (ip->iph_ihl *4) + (tcp->tcp_offset *4) + i]);
     }
     printf("\n");
   }
 }
}
int main()
{
 pcap_t *handle; // pcap 핸들러
char errbuf[PCAP_ERRBUF_SIZE]; // 에러 버퍼
struct bpf_program fp; // 필터 프로그램
char filter_exp[] ="tcp"; // 필터 표현식
 bpf_u_int32 net; // 네트워크 주소
// 1단계: NIC에서 라이브 pcap 세션 열기 (이름: enp0s3 같은)
 handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
// 2단계: filter_exp를 BPF 의사 코드로 컴파일
 pcap_compile(handle, &fp, filter_exp, 0, net);
if (pcap_setfilter(handle, &fp) !=0) {
     pcap_perror(handle, "Error:");
     exit(EXIT_FAILURE);
 }
// 3단계: 패킷 캡처
 pcap_loop(handle, -1, got_packet, NULL);
 pcap_close(handle);   // 핸들 닫기
return 0;
}