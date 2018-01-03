#include <string>

#include "exception.h"

pcap_setup_exception::pcap_setup_exception(std::string msg)
    : msg(std::string("Error occurred while setting up pcap: ") + msg)
{}

const char* pcap_setup_exception::what() const noexcept {
    return msg.c_str();
}
