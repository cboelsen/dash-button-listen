#pragma once

#include <exception>
#include <string>

class pcap_setup_exception: public std::exception
{
    public:
        pcap_setup_exception(std::string msg);
        virtual const char* what() const noexcept;
    private:
        const std::string msg;
};
