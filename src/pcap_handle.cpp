#include <pcap.h>

#include <string>

#include "exception.h"
#include "pcap_handle.h"

// default snap length (maximum bytes per packet to capture)
#define SNAP_LEN 1518

PcapHandle::PcapHandle()
    : handle(nullptr)
{}
PcapHandle::~PcapHandle() {
    if (handle)
        pcap_close(handle);
}
pcap_t *PcapHandle::get() const {
    return handle;
}
void PcapHandle::open(std::string dev) {
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(dev.c_str(), SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        throw pcap_setup_exception(std::string("Couldn't open device ") + dev + ": " + errbuf);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        throw pcap_setup_exception(dev + " is not an ethernet device");
    }
}
