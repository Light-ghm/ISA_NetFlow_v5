#define __FAVOR_BSD //musel som dať __FAVOR_BSD pred každú knihovnu čo ma niečo so sieťami inak to nešlo preložiť na Merlinovi
#include<iostream>
#include<stdio.h>
#include<ctype.h>
#include<stdlib.h>
#include<getopt.h>
#include<unistd.h> 
#include<pcap.h>
#include<err.h>
#include<errno.h>
#include<assert.h>
#include<string.h>
#define __FAVOR_BSD
#include"flow.h"
#include<sys/socket.h>
#define __FAVOR_BSD
#include<netdb.h>
#include<tuple>
#include<map>
#include<string>
#define __FAVOR_BSD
#include<sys/socket.h>
#define __FAVOR_BSD
#include<netinet/in.h>
#define __FAVOR_BSD
#include<netinet/ip.h>
#define __FAVOR_BSD
#include<arpa/inet.h>
#define __FAVOR_BSD
#include<netinet/if_ether.h> 
#include <vector>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#ifdef __linux__ 
#include <netinet/ether.h> 
#include <time.h>
#endif
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif
#define SIZE_ETHERNET (14)

//štruktúra ktorá udržiava informácie o collectore 
typedef struct nf_collector_t{
  int socket;
  struct sockaddr_in sockaddr;
} nf_collector_t;

//Globálne časové premenné
static unsigned long current_sec;
static unsigned long current_msec;
static unsigned long current_usec;
static unsigned long current_nsec;
static unsigned long sys_boot_sec;
static unsigned long sys_boot_msec;
static unsigned long sys_boot_usec;
static unsigned long sys_boot_nsec;

//Ostatné globálne premenné 
unsigned int total_flows = 0;
uint8_t ToS = 0;
uint16_t IP_size = 0;
uint32_t IP_packet_size = 0;
int m = 1024; // max. počet flowov v cachi (mape v mojom prípade)
static nf_collector_t nf_collector;
long long a = 60;
long long i = 10;
//Typedef tuple pre rozpoznávanie jednotlivých flowov na základe:
//src_ip, dst_ip, src_port, dst_port, protokol
//je to klúč do mapy pre nájdenie flow-u
typedef std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> tuple_key;

//cache (mapa) pre flowi
std::map<tuple_key,struct flowrecord> flow_map;

//vektor klúčov na export
std::vector<tuple_key> flow_keys_to_export;

//vektor klúčov na odobranie z mapy
//keďže klúčov na export môže byť max. 30,
//tak ak sa to prekročí, exportujem flowi podľa daných klúčov
//a vektor flow_keys_to_export vyprýzdnim, a keďže nechcem
//vymazávať v mape cez ktorú práve cyklím, tak mám osobitný
//vektor flow_keys_to_remove podľa ktorého vymažem všetky
//flowi ktoré som v cykli exportoval z mapy až po ukončení cyklu
std::vector<tuple_key> flow_keys_to_remove;

// ---------------------------------  funkcie na prácu s časom ------------------------------------------------
//na začiatku programu vynuluje všetky pomocné časové premenné
void time_reset() {
  current_sec = 0;
  current_msec = 0;
  current_usec = 0;
  current_nsec = 0;
  sys_boot_sec = 0;
  sys_boot_msec = 0;
  sys_boot_nsec = 0;
}
//updatene časové premenné na čas aktuálne spracúvavaného pcap packetu
void time_update(const struct timeval *new_time) {
  //sys_boot časové premenné sa nastavujú iba na hodnotu úplne prvého pcap packetu
  if (current_sec == 0 && sys_boot_sec == 0) {
    sys_boot_sec = new_time->tv_sec;
    sys_boot_msec = new_time->tv_usec/1000;
    sys_boot_usec = new_time->tv_usec;
    sys_boot_nsec = new_time->tv_usec * 1000;
  }
  current_sec = new_time->tv_sec;
  current_msec = new_time->tv_usec /1000;
  current_usec = new_time->tv_usec;
  current_nsec = new_time->tv_usec * 1000;
}

//Vyráta koľko mikrosekúnd prešlo medzi časom aktuálneho paketu a boot časom (časom úplne prvého paketu)
unsigned long time_sysuptime() {
  if(current_usec > sys_boot_usec) return ((1000000 * (current_sec - sys_boot_sec)) + (current_usec - sys_boot_usec));
  else {
    return ((1000000 * (current_sec - sys_boot_sec)) - (sys_boot_usec - current_usec));
  }
  
}

//----------------------  Funkcia pre inicializáciu socketu k netflow collectoru  ----------------------------------------
void nf_init_collector(nf_collector_t *collector, struct in_addr *collector_ip, unsigned short collector_port) {
  int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s < 0) {
    fprintf(stderr, "Nepodarilo sa inicializovať SOCKET!\n");
    exit(1);
  }
  collector->socket = s;
  collector->sockaddr.sin_family = AF_INET;
  collector->sockaddr.sin_port = htons(collector_port);
  memcpy(&collector->sockaddr.sin_addr, collector_ip, sizeof(struct in_addr));
}

// ---------------------------------- Funkcie na prácu s flow rekordmi ------------------------------------------

//Pošle na collector cez UDP všetky flowi ktoré majú klúč v argumente flow_keys_to_export
void nf_send_to_collector(nf_collector_t *collector, std::vector<tuple_key> * flow_keys_to_export){
  flowpacket flowpack;
  
  flowpack.nf_header.version = htons(5);
  flowpack.nf_header.count = htons(uint16_t((flow_keys_to_export->size())));
  flowpack.nf_header.SysUptime = htonl(time_sysuptime()/1000);
  flowpack.nf_header.unix_secs = htonl(current_sec);
  flowpack.nf_header.unix_nsecs = htonl(current_nsec);
  flowpack.nf_header.flow_sequence = htonl(total_flows);
  flowpack.nf_header.engine_type = 0;
  flowpack.nf_header.engine_id = 0;
  flowpack.nf_header.sampling_interval = 0;
  int i = 0;
  for(auto it = flow_keys_to_export->begin(); it != flow_keys_to_export->end(); ++it){
    auto m_it = flow_map.find(*it);
    if ( m_it == flow_map.end() ) {  
      continue;
    }
    flowrecord *flow_rec = &m_it->second;
    flowpack.nf_record[i] = m_it->second.nf_record;
    flowpack.nf_record[i].first = htonl(flow_rec->nf_record.first/1000);
    flowpack.nf_record[i].last= htonl(flow_rec->nf_record.last/1000);
    flowpack.nf_record[i].dPkts = htonl(flow_rec->nf_record.dPkts);
    flowpack.nf_record[i].dOctets = htonl(flow_rec->nf_record.dOctets);
    
    i++;
  }

  int err = sendto( collector->socket, &flowpack, (sizeof(nf_v5_header_t) + (sizeof(nf_v5_record_t) * flow_keys_to_export->size())), 0, 
                      (struct sockaddr *)&collector->sockaddr, sizeof(struct sockaddr_in));
  if (err < 0) {
    fprintf(stderr, "Chyba, nepodarilo sa exportovať na collector %d: %s\n", collector->socket, strerror(errno));
  }
  total_flows += flow_keys_to_export->size();

}

//Funkcia vráti ukazateľ na flowrecord v mape na základe klúča zostaveného z argumentov,
//pokiaľ sa flow s daným klúčom v mape nenachádza, tak sa aj skontroluje sa či je v mape ešte miesto(nie je plná cache),
//ak je plná, uvolní sa najstarší flow(flow s najmenším 'first' časom)
//a vytvorí sa nový flow, taktiež sa tu kontroluje active timer flowov taktiež sa tu updatujú informácie o flowe na základe najnovšieho packetu
flowrecord *get_flow(uint32_t source_ip, uint32_t destination_ip, uint16_t source_port, uint16_t destination_port, uint8_t protocol, uint32_t data_size, uint8_t tcp_flags){
  
  std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> tuple_key_l(source_ip, destination_ip, source_port, destination_port, protocol);
  
  //ak sa dorazí až na koniec mapy, tak tam zadaný klúč nie je
  if (flow_map.find(tuple_key_l) == flow_map.end()) {
    //kontrola počtu flowov
    if(flow_map.size() >= m){
      tuple_key oldest_flow_key = flow_map.begin()->first;
      for (auto i = flow_map.begin(); i != flow_map.end();  ++i) {
        //zistí najstarši paket (najstarší v zmysle naposledy updatovaný - najdlhšie mu nebol priradený paket)
        if((i->second.nf_record.last) < (flow_map.find(oldest_flow_key)->second.nf_record.last)){
          oldest_flow_key = i->first;
        }
      }
      flow_keys_to_export.push_back(oldest_flow_key);
      nf_send_to_collector(&nf_collector, &flow_keys_to_export);
      flow_keys_to_export.clear();
      flow_map.erase(oldest_flow_key);
    }
    //vytvorenie nového flow záznamu, inicializácia niektorých položiek a vloženie do mapy
    flowrecord *f_rec = new flowrecord;
    f_rec->nf_record.srcaddr = htonl(source_ip);
    f_rec->nf_record.dstaddr = htonl(destination_ip);
    f_rec->nf_record.srcport = htons(source_port);
    f_rec->nf_record.dstport = htons(destination_port);
    f_rec->nf_record.prot = protocol;
    f_rec->nf_record.first = 0;
    f_rec->nf_record.dPkts = 0;
    f_rec->nf_record.nexthop = 0;
    f_rec->nf_record.input = 0;
    f_rec->nf_record.output = 0;
    
    f_rec->nf_record.dOctets = 0;
    f_rec->nf_record.pad1 = 0;
    f_rec->nf_record.tos = ToS;
    f_rec->nf_record.src_as = 0;
    f_rec->nf_record.dst_as = 0;
    f_rec->nf_record.src_mask = 32;
    f_rec->nf_record.dst_mask = 32;
    f_rec->nf_record.pad2 = 0;

    //získavanie všetkých TCP flagov ktoré nastali v flowe
    if(protocol == 6){
      //oba sú rovno v network byte orderi tak nemusím ani prevádzať
      f_rec->nf_record.tcp_flags |= tcp_flags;
    }
    //update First/Last časov
    f_rec->nf_record.first = time_sysuptime();
    f_rec->nf_record.last = f_rec->nf_record.first;
      

    //update počtu packetov a počtu bytov vo flowe
    f_rec->nf_record.dOctets += data_size;
    f_rec->nf_record.dPkts++;

    flow_map[tuple_key_l] = *f_rec;
  }else{

    //získavanie všetkých TCP flagov ktoré nastali v flowe
    if(protocol == 6){
      //oba sú rovno v network byte orderi tak nemusím ani prevádzať
      flow_map[tuple_key_l].nf_record.tcp_flags |= tcp_flags;
    }
    //update Last času
    flow_map[tuple_key_l].nf_record.last = time_sysuptime();
      
    //update počtu packetov a počtu bytov vo flowe
    flow_map[tuple_key_l].nf_record.dOctets += data_size;
    flow_map[tuple_key_l].nf_record.dPkts++;

    //Kontrola na expirenute flow recordy
    flow_keys_to_export.clear();
    flow_keys_to_remove.clear();

    if ((((signed long long)flow_map[tuple_key_l].nf_record.last) - ((signed long long)flow_map[tuple_key_l].nf_record.first)) > a){
      flow_keys_to_export.push_back(tuple_key_l);
      flow_keys_to_remove.push_back(tuple_key_l);
    
      
      //ak sú nejaké klúče na export tak exportuj
      if(flow_keys_to_export.size() > 0){
        nf_send_to_collector(&nf_collector, &flow_keys_to_export);
      }

      flow_keys_to_export.clear();

      //vymaž exportované záznamy z mapy
      for(auto it = flow_keys_to_remove.begin(); it != flow_keys_to_remove.end(); ++it){
        flow_map.erase(*it);
      }
      flow_keys_to_remove.clear();
    }
  }

  return &flow_map[tuple_key_l];
}

//------------------------------------------------------  main  -----------------------------------------------------
// ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]
int main(int argc, char **argv){
    struct hostent *host_name;
    struct in_addr **IPlist;
    int opt;
    int index;
    opterr = 0;
    int a_flag = 0;
    int i_flag = 0;
    int m_flag = 0;
    int f_flag = 0;
    int c_flag = 0;
    uint8_t tcpflags = 0;
    std::string f = "-";
    std::string c = "127.0.0.1:2055";
    std::string c_IP ="127.0.0.1";
    uint16_t c_port;
    std::string c_ports ="";

    //spracovanie argumentov pomocou getopt()  
    while ((opt = getopt(argc,argv,"f:c:a:i:m:")) != EOF)
        
        switch(opt)
        {
            case 'f': f_flag = 1; f = optarg; break;
            case 'c': c_flag = 1; c = optarg; break;
            case 'a': 
                try{
                    a_flag = 1; a = std::stoi(optarg);
                }catch(...){
                    fprintf(stderr, "Chyba! Active timer flag: -a vyžaduje parameter typu <int>!");
                    exit(1);
                }
                break;
                
            case 'i': 
                try{
                    i_flag = 1; i = std::stoi(optarg);
                }catch(...){
                    fprintf(stderr, "Chyba! Inactive timer flag: -i vyžaduje parameter typu <int>!");
                    exit(1);
                }
                break;
                
            case 'm': 
                try{
                    m_flag = 1; m = std::stoi(optarg);
                }catch(...){
                    fprintf(stderr, "Chyba! Count flag: -m vyžaduje parameter typu <int>!");
                    exit(1);
                }
                break;
                
            case '?': 
                if (optopt == 'f' || optopt == 'c' || optopt == 'a' || optopt == 'i' || optopt == 'm') fprintf (stderr, "Flag -%c vyžaduje argument.\n", optopt);
                else if (isprint (optopt)) fprintf (stderr, "Neznámy flag: `-%c'.\n", optopt);
                else fprintf(stderr, "Použitie:\n./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>] \nVšetky flagy sú nepovinné. \n");
                exit(1);
            default: std::cout<<std::endl; abort();
        }
    //kontrola na prebytočné argumenty
    int total_args = a_flag*2  +i_flag*2 + m_flag*2 + f_flag*2 + c_flag*2 + 1;
    if (total_args < argc){
        fprintf(stderr, "Prílyž veľa argumentov!\nPoužitie: \n./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>] \nVšetky flagy sú nepovinné. \n");
        exit(1);
    }

    //prevádzanie hodnôt časovačov na microsekundy, lebo sysuptime s ktorým ich porovnávame je v ms
    a = a * 1000000;
    i = i * 1000000;
    
    //rozdelenie IP a portu z argumentu
    size_t pos = 0;
    std::string delimiter = ":";
    if((pos = c.find(delimiter)) != std::string::npos){
      c_IP = c.substr(0, pos);
      c.erase(0, pos + delimiter.length());
      c_ports = c;
    }else{
      c_IP = c;
      c_ports = "2055";
    }
    
    //prevod portu z typu string na typ int
    try{
      c_port = std::stoi(c_ports);
    }catch(...){
      fprintf(stderr, "Chyba! Port musí byť typu <u_int16>!\n");
      exit(1);
    }

    //prevod hostname na IP formát
    if((host_name=gethostbyname(c_IP.c_str())) == NULL){
      fprintf(stderr, "Chyba! Nepodarilo sa resolvnut hostname!\n");
      exit(1);
    }
    IPlist =(struct in_addr **) host_name->h_addr_list;
    int check = 1;
    for(int i=0; IPlist[i] !=NULL; i++){
      c_IP= inet_ntoa(*IPlist[i]);
      check--;
      break;
    }

    if(check){
      fprintf(stderr, "Chyba! Nepodarilo sa nakoniec resolvnut hostname!\n");
      exit(1);
    }
    
    //prechádzanie pcap súboru a získavanie potrebných dát
    
    //premenná potrebné k prechádzaniu pcap-u a získavaniu informácií z pcap/ethernet/ip/tcp/udp/icmp hlavićiek
    
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct ip *my_ip;
    const struct tcphdr *my_tcp;
    const struct udphdr *my_udp;
    struct pcap_pkthdr header;  
    struct ether_header *eptr;
    pcap_t *handle;
    

    uint32_t source_ip;
    uint32_t destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t protocol;
    uint32_t data_size = 0;
    //Inicializovanie premenných a socketu pre spojenie s collectorom
    struct in_addr collector_ip;
    inet_aton(c_IP.c_str(), &collector_ip);
    nf_init_collector(&nf_collector, &collector_ip, c_port);
    
    //otváranie pcap-u
    if ((handle = pcap_open_offline(f.c_str(),errbuf)) == NULL) err(1,"Nemožno otvoriť file %s!",f.c_str());

    //vynulovanie časových premenných
    time_reset();

    //Cyklenie po jednotlivých packetoch z pcap-u, získavanie informácí z hlavičiek, vytváranie, kontrola a export tokov
    //Prechádzanie .pcap súboru a čítanie hlavičiek čiastočne inšpirované z read-pcap.c súboru,
    //ktorý bol ukázaný na prednáške ISA a je v súboroch predmetu v elearning-u.
    while ((packet = pcap_next(handle,&header)) != NULL){
      ToS = 0;
      flowrecord *flowrecord;

      //updatovanie časových premenných na čas aktuálneho paketu
      time_update(&header.ts);

      // read the Ethernet header
      eptr = (struct ether_header *) packet;
      
      switch (ntohs(eptr->ether_type)){
        case ETHERTYPE_IP:        // IPv4 packet
          
          my_ip = (struct ip*) (packet+SIZE_ETHERNET);
          source_ip = ntohl(my_ip->ip_src.s_addr);
          destination_ip = ntohl(my_ip->ip_dst.s_addr);
          ToS = my_ip->ip_tos;
          protocol = my_ip->ip_p;
          IP_size = my_ip->ip_hl*4;
          IP_packet_size = ntohs(my_ip->ip_len);

          switch (protocol){
            case 1: //ICMP protocol
              data_size = IP_packet_size - IP_size - 8;
              source_port = 0;
              destination_port = 0; 
              tcpflags = 0;
	            break;
            case 6: // TCP protocol
	            my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+IP_size); // pointer to the TCP header
              data_size = IP_packet_size - IP_size;
              source_port = ntohs(my_tcp->th_sport);
              destination_port = ntohs(my_tcp->th_dport);
              tcpflags = my_tcp->th_flags;
	            break;
            case 17: // UDP protocol
	            my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+IP_size); // pointer to the UDP header
	            source_port = ntohs(my_udp->uh_sport);
              destination_port = ntohs(my_udp->uh_dport);
              data_size = IP_packet_size - IP_size - 8;
              tcpflags = 0;
              break;
            default:
              //spracovávame len TCP/UDP/ICMP
              continue;
              break;
          }

          break;
      
        default:
          //spracovávame len IPv4
          continue;
          break;
      } 
      
      //Kontrola na expirenute flow recordy - inactive timer
      flow_keys_to_export.clear();
      flow_keys_to_remove.clear();
      for (auto it = flow_map.begin(); it != flow_map.end(); ++it) {
       
        if((((signed long long)time_sysuptime()) - (signed long long)it->second.nf_record.last) > i){ //flow je stary a treba ho dat na export
          
          //Ak už je pripravených 30 záznamov na export,tak exportuj a následne vyčisti vektor klúčov na export
          if(flow_keys_to_export.size() >= 30){
            nf_send_to_collector(&nf_collector, &flow_keys_to_export);
            flow_keys_to_export.clear();
          }
          flow_keys_to_export.push_back(it->first);
          flow_keys_to_remove.push_back(it->first);
        }

      }
      //ak sú nejaké klúče na export tak exportuj
      if(flow_keys_to_export.size() > 0){
        nf_send_to_collector(&nf_collector, &flow_keys_to_export);
      }

      flow_keys_to_export.clear();

      //vymaž exportované záznamy z mapy
      for(auto it = flow_keys_to_remove.begin(); it != flow_keys_to_remove.end(); ++it){
        flow_map.erase(*it);
      }
      flow_keys_to_remove.clear();

      //získaj ukazateľ na flow z mapy do ktorého patrí aktuálny packet z pcap-u
      flowrecord = get_flow(source_ip, destination_ip, source_port, destination_port, protocol, data_size, tcpflags);
      
      //Ak sme z nejakého dôvodu nedostali validný ukazateľ na flow tak continue - nemalo by sa nikdy stať
      if (flowrecord == NULL) {
        fprintf(stderr, "Nepodarilo sa získať flow record!\n");
        continue;
      } 
    
    }
    
    //boli spracovane všetky packety tak program vyexportuje všetky flowi z mapy
    flow_keys_to_export.clear();
    flow_keys_to_remove.clear();
    for (auto it = flow_map.begin(); it != flow_map.end(); ++it) {
      
       
      if(flow_keys_to_export.size() >= 30){
        nf_send_to_collector(&nf_collector, &flow_keys_to_export);
        flow_keys_to_export.clear();
      }
      flow_keys_to_export.push_back(it->first);
      flow_keys_to_remove.push_back(it->first);
          
    }
    nf_send_to_collector(&nf_collector, &flow_keys_to_export);
    flow_keys_to_export.clear();

    //vymazanie flowov z mapy
    for(auto it = flow_keys_to_remove.begin(); it != flow_keys_to_remove.end(); ++it){
      flow_map.erase(*it);
    }
    flow_keys_to_remove.clear();
    
    //koniec práce s pcap-om a koniec programu
    pcap_close(handle);
    return 0;
}
