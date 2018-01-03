#pragma once

#include <pcap.h>

#include <string>

class PcapHandle {
    public:
        PcapHandle();
        ~PcapHandle();
        pcap_t *get() const;
        void open(std::string dev);
    private:
        pcap_t *handle;
};
