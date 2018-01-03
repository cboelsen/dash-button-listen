# distutils: language=c++
# distutils: sources=src/sniffer.cpp src/filter_program.cpp src/pcap_handle.cpp src/exception.cpp


from libcpp cimport bool
from libcpp.string cimport string
from cython.operator cimport dereference as deref, preincrement as inc


cdef extern from "pcap.h":
    ctypedef struct pcap_t:
        pass


cdef extern from "sniffer.h":
    cdef cppclass DhcpSniffer:
        cppclass iterator:
            iterator() except +
            iterator(pcap_t *handle, string mac="") except +
            iterator& operator++()
            iterator operator++(int)
            bool operator==(iterator other)
            bool operator!=(iterator other)
            string operator*()
        DhcpSniffer(string dev) except +
        iterator begin()
        iterator end()


cdef class PyDhcpSniffer:
    cdef DhcpSniffer* c_sniffer

    def __cinit__(self, dev):
        self.c_sniffer = new DhcpSniffer(dev.encode())

    def __dealloc__(self):
        del self.c_sniffer

    def mac_addresses(self):
        cdef DhcpSniffer.iterator it = self.c_sniffer.begin()
        cdef DhcpSniffer.iterator end = self.c_sniffer.end()
        while it != end:
            yield deref(it).decode()
            inc(it)
