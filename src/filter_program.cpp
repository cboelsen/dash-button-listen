#include <pcap.h>
#include <netinet/ether.h>

#include <iostream>
#include <string>

#include "exception.h"
#include "filter_program.h"

FilterProgram::FilterProgram()
    : fp()
{}
FilterProgram::~FilterProgram() {
    pcap_freecode(&fp);
}
void FilterProgram::set(PcapHandle &handle, std::string filter_exp, bpf_u_int32 net) {
    if (pcap_compile(handle.get(), &fp, filter_exp.c_str(), 0, net) == -1) {
        throw pcap_setup_exception(std::string("Couldn't parse filter ") + filter_exp + ": " + pcap_geterr(handle.get()));
    }

    if (pcap_setfilter(handle.get(), &fp) == -1) {
        throw pcap_setup_exception(std::string("Couldn't install filter ") + filter_exp + ": " + pcap_geterr(handle.get()));
    }
}
