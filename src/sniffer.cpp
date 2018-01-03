#include <pcap.h>
#include <netinet/ether.h>

#include <iostream>
#include <string>

#include "sniffer.h"

static std::string get_mac(const u_char *packet)
{
    const struct ether_header *eptr = (struct ether_header *) packet;
    return ether_ntoa((struct ether_addr*)eptr->ether_shost);
}

std::string DhcpSniffer::iterator::next() const {
    struct pcap_pkthdr hdr;
    const u_char *packet = pcap_next(handle, &hdr);
    if (packet) {
        return get_mac(packet);
    }
    return "";
}
DhcpSniffer::iterator::iterator()
    : iterator(nullptr, "a")
{}
DhcpSniffer::iterator::iterator(pcap_t *handle, std::string mac)
    : mac(mac)
    , handle(handle)
{
    if (mac.empty()) {
        ++(*this);
    }
}
DhcpSniffer::iterator& DhcpSniffer::iterator::operator++() {
    do {
        mac = next();
    } while(mac.empty());
    return *this;
}
DhcpSniffer::iterator DhcpSniffer::iterator::operator++(int) {
    iterator retval = *this;
    ++(*this);
    return retval;
}
bool DhcpSniffer::iterator::operator==(iterator other) const {
    return mac == other.mac;
}
bool DhcpSniffer::iterator::operator!=(iterator other) const {
    return !(*this == other);
}
std::string DhcpSniffer::iterator::operator*() const {
    return mac;
}

DhcpSniffer::DhcpSniffer(std::string dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    char dhcp_filter[] = "(udp and (port 67 or 68))";
    //char dhcp_filter[] = "udp";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev.c_str(), &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get address and netmask for device %s: %s\n",
                dev.c_str(), errbuf);
        net = 0;
        mask = 0;
    }

    handle.open(dev);
    fp.set(handle, dhcp_filter, net);
}

DhcpSniffer::iterator DhcpSniffer::begin() {
    return DhcpSniffer::iterator(handle.get());
}

DhcpSniffer::iterator DhcpSniffer::end() {
    return DhcpSniffer::iterator(handle.get(), "no end");
}
