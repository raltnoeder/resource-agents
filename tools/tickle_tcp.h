/**
 * "Tickle-ACK" TCP connection failover support utility
 *
 * Author: Robert Altnoeder
 * Derived from prior work authored by Jiaju Zhang, Andrew Tridgell, Ronnie Sahlberg
 * and the Samba project.
 *
 * This file is part of tickle_tcp.
 *
 * tickle_tcp is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * tickle_tcp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with tickle_tcp.  If not, see <https://www.gnu.org/licenses/>
 */

#ifndef TICKLE_TCP_H
#define TICKLE_TCP_H

#include <cstdint>
#include <string>
#include <stdexcept>

extern "C"
{
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/ip6.h>
}

namespace application
{
    // Application exit codes
    constexpr int ERR_GENERIC       = 1;
    constexpr int ERR_OUT_OF_MEMORY = 2;
    constexpr int ERR_IO            = 3;

    // Buffer for input lines read from stdin
    constexpr std::streamsize LINE_BUFFER_SIZE = 140;

    // Buffer for translation of IP addresses to strings
    constexpr size_t ADDRESS_BUFFER_SIZE = 60;

    // Default number of packets to send to each destination
    constexpr uint16_t DEFAULT_PACKET_COUNT = 1;

    // TCP flags values
    constexpr uint8_t TCP_FIN = 0x01;
    constexpr uint8_t TCP_SYN = 0x02;
    constexpr uint8_t TCP_RST = 0x04;
    constexpr uint8_t TCP_PSH = 0x08;
    constexpr uint8_t TCP_ACK = 0x10;
    constexpr uint8_t TCP_URG = 0x20;
    constexpr uint8_t TCP_ECE = 0x40;
    constexpr uint8_t TCP_CWR = 0x80;

    // Error messages
    const char* const ERRMSG_OUT_OF_MEMORY          = "Out of memory";
    const char* const ERRMSG_INVALID_NR             = "Unparsable number";
    const char* const ERRMSG_INVALID_PORT_NR        = "Invalid port number";
    const char* const ERRMSG_UNPARSABLE_ENDPOINT    = "Unparsable IP address:port string";
    const char* const ERRMSG_INVALID_IP_ADDRESS     = "Invalid IP address";
    const char* const ERRMSG_INVALID_ADDR_FAM       = "Unsupported address family";
    const char* const ERRMSG_FCNTL_FAIL             = "I/O error: Changing the mode of a file descriptor failed";
    const char* const ERRMSG_INET_PTON_FAIL         =
        "Library function inet_pton(...) returned an unexpected return code";
    const char* const ERRMSG_SETSOCKOPT_FAIL        =
        "I/O error: Adjusting socket options failed";
    const char* const ERRMSG_UNUSABLE_LINKLOCAL     =
        "Unusable IPv6 link-local address: Missing network interface specifier (%name suffix)";
    const char* const ERRMSG_LINKLOCAL_NO_NETIF     =
        "Nonexistent IPv6 link-local network interface";
    const char* const ERRMSG_SOCKET_RAW_FAIL        = "I/O error: Creation of a raw IP protocol socket failed";
    const char* const ERRMSG_STDIN_IO               =
        "Error: I/O error while reading input from stdin, cannot continue";

    const std::string OPT_PACKET_COUNT("-n");
    const std::string OPT_HELP("-h");
    const std::string LONG_OPT_HELP("--help");

    class AnnotatedException : public std::exception
    {
      private:
        int exc_error_nr;
        std::string exc_error_msg;

      public:
        // @throws std::bad_alloc
        AnnotatedException(int error_nr, const char* error_msg);
        // @throws std::bad_alloc
        AnnotatedException(int error_nr, const std::string& error_msg);
        virtual ~AnnotatedException() noexcept;
        AnnotatedException(const AnnotatedException& other) = default;
        AnnotatedException(AnnotatedException&& orig) = default;
        virtual AnnotatedException& operator=(const AnnotatedException& other) = default;
        virtual AnnotatedException& operator=(AnnotatedException&& orig) = default;
        virtual const char* what() const noexcept override;
        virtual int get_error_nr() const noexcept;
    };

    class AutoClose
    {
      private:
        int ac_file_dsc;
      public:
        AutoClose(int file_dsc);
        virtual ~AutoClose() noexcept;
        // Copy/move deleted, since those are not used anywhere
        AutoClose(const AutoClose& other) = delete;
        AutoClose(AutoClose&& orig) = delete;
        virtual AutoClose& operator=(const AutoClose& other) = delete;
        virtual AutoClose& operator=(AutoClose&& orig) = delete;
    };

    struct ipv4_header_no_opt
    {
        // Version, Length:
        // Version:     4 bits  (mask 0xF0)
        // Length:      4 bits  (mask 0x0F)
        uint8_t         vsn_length;
        // Type of service: DSCP, ECN
        // DSCP:        6 bits  (mask 0xFC)
        // ECN:         2 bits  (mask 0x03)
        uint8_t         tos;
        uint16_t        length;
        uint16_t        id;
        // Flags, fragment offset:
        // Flags:       3 bits  (mask 0xE000)
        // Frg offset:  13 bits (mask 0x1FFF)
        uint16_t        flags_frg_off;
        uint8_t         ttl;
        uint8_t         protocol;
        uint16_t        chksum;
        struct in_addr  src_address;
        struct in_addr  dst_address;
    };

    struct ipv6_header
    {
        // Version, Traffic class, Flow label:
        // Version:         4 bits  (mask 0xF0000000)
        // Traffic class:   8 bits  (mask 0x0FF00000)
        // Flow label:      20 bits (mask 0x000FFFFF)
        uint32_t    vsn_cls_flowlbl;
        uint16_t    length;
        uint8_t     next_header;
        uint8_t     hop_limit;
        uint8_t     src_address[16];
        uint8_t     dst_address[16];
    };

    struct proto_tcp_header
    {
        uint16_t    src_port;
        uint16_t    dst_port;
        uint32_t    seq_nr;
        uint32_t    ack_nr;
        // Combined (from high order bits to low order bits):
        // data offset (4 bits), reserved (3 bits), ns (1 bit)
        uint8_t     cmb_data_off_ns;
        uint8_t     tcp_flags;
        uint16_t    window_size;
        uint16_t    checksum;
        uint16_t    urgent_ptr;
    };

    struct ipv4_packet
    {
        ipv4_header_no_opt  ip_header;
        proto_tcp_header    tcp_header;
    };

    struct ipv6_packet
    {
        ipv6_header         ip_header;
        proto_tcp_header    tcp_header;
    };

    // @throws std::bad_alloc, AnnotatedException
    int run(uint16_t packet_count);
    // @throws std::bad_alloc, AnnotatedException
    void display_help() noexcept;
    void display_error_nr_msg(int error_nr) noexcept;
    bool parse_arguments(int argc, char* argv[], uint16_t& packet_count);
    // @throws std::bad_alloc, AnnotatedException
    void split_address_and_port(const std::string& address_and_port, std::string& address, std::string& port);
    // @throws std::bad_alloc, AnnotatedException
    void split_address_and_netif(std::string& address, std::string& netif);
    // @throws std::bad_alloc
    void trim_lead(std::string& text);
    // @throws std::bad_alloc
    void trim_trail(std::string& text);
    // @throws std::bad_alloc, AnnotatedException
    uint16_t parse_uint16(const std::string& number);
    // @throws std::bad_alloc, AnnotatedException
    uint16_t parse_port_number(const std::string& number);
    // @throws std::bad_alloc, AnnotatedException
    void parse_ipv4(
        const std::string&  address_input,
        const std::string&  port_input,
        struct sockaddr_in& address
    );
    // @throws AnnotatedException
    void parse_ipv6(
        const std::string&      address_input,
        const std::string*      netif_input,
        const std::string&      port_input,
        struct sockaddr_in6&    address
    );
    void send_ipv4_packet(
        ipv4_packet&        packet,
        const sockaddr_in&  src_address,
        const sockaddr_in&  dst_address,
        uint16_t            packet_count
    );
    // @throws std::bad_alloc, AnnotatedException
    void send_ipv6_packet(
        ipv6_packet&        packet,
        const sockaddr_in6& src_address,
        const sockaddr_in6& dst_address,
        uint16_t            packet_count
    );
    // @throws std::bad_alloc, AnnotatedException
    void send_packet(
        const int               socket_domain,
        const struct sockaddr*  dst_address,
        size_t                  dst_address_size,
        uint16_t                dst_port,
        const void*             packet_data,
        size_t                  packet_data_size,
        uint16_t                packet_count
    );
    // @throws AnnotatedException
    void check_inet_pton_rc(int rc, int error_nr);
    // @throws std::bad_alloc, AnnotatedException
    void set_fcntl_flags(int file_dsc, int flags);
    // @throws std::bad_alloc, AnnotatedException
    uint16_t ipv4_tcp_checksum(
        const unsigned char*        data,
        size_t                      length,
        const ipv4_header_no_opt*   header
    ) noexcept;
    uint16_t ipv6_tcp_checksum(
        const unsigned char*    data,
        size_t                  length,
        const ipv6_header*      header
    ) noexcept;
    uint32_t checksum(const unsigned char* data, size_t length) noexcept;
}

#endif /* TICKLE_TCP_H */
