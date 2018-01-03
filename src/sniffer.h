#pragma once

#include <pcap.h>

#include <string>

#include "filter_program.h"
#include "pcap_handle.h"

class DhcpSniffer {
    public:
        class iterator: public std::iterator<std::input_iterator_tag, std::string> {
            std::string next() const;
            std::string mac;
            pcap_t *handle;
        public:
            iterator();
            explicit iterator(pcap_t *handle, std::string mac = "");
            iterator& operator++();
            iterator operator++(int);
            bool operator==(iterator other) const;
            bool operator!=(iterator other) const;
            std::string operator*() const;
        };

        DhcpSniffer(std::string dev);
        iterator begin();
        iterator end();

    private:
        PcapHandle handle;
        FilterProgram fp;
};
