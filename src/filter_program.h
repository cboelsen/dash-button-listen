#pragma once

#include <pcap.h>

#include <string>

#include "pcap_handle.h"

class FilterProgram {
    public:
        FilterProgram();
        ~FilterProgram();
        void set(PcapHandle &handle, std::string filter_exp, bpf_u_int32 net);
    private:
        struct bpf_program fp;
};
