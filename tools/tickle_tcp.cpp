#include "tickle_tcp.h"

#include <iostream>
#include <cstring>
#include <new>
#include <memory>

extern "C"
{
    #include <fcntl.h>
    #include <arpa/inet.h>
    #include <netinet/tcp.h>
    #include <net/if.h>
    #include <errno.h>
}

// Invokes the arguments parser, then the application's main I/O loop
int main(int argc, char* argv[])
{
    int rc = application::ERR_GENERIC;
    try
    {
        uint16_t packet_count = application::DEFAULT_PACKET_COUNT;
        if (application::parse_arguments(argc, argv, packet_count))
        {
            rc = application::run(packet_count);
        }
    }
    catch (application::AnnotatedException& exc)
    {
        std::cerr << "Error: " << exc.what() << std::endl;
        application::display_error_nr_msg(exc.get_error_nr());
    }
    catch (std::bad_alloc&)
    {
        std::cerr << "Error: " << application::ERRMSG_OUT_OF_MEMORY << std::endl;
    }

    return rc;
}

namespace application
{
    // @throws std::bad_alloc
    AnnotatedException::AnnotatedException(const int error_nr, const char* const error_msg):
        exc_error_nr(error_nr),
        exc_error_msg(error_msg)
    {
    }

    // @throws std::bad_alloc
    AnnotatedException::AnnotatedException(const int error_nr, const std::string& error_msg):
        exc_error_nr(error_nr),
        exc_error_msg(error_msg)
    {
    }

    AnnotatedException::~AnnotatedException() noexcept
    {
    }

    const char* AnnotatedException::what() const noexcept
    {
        return exc_error_msg.c_str();
    }

    int AnnotatedException::get_error_nr() const noexcept
    {
        return exc_error_nr;
    }

    AutoClose::AutoClose(const int file_dsc)
    {
        ac_file_dsc = file_dsc;
    }

    AutoClose::~AutoClose() noexcept
    {
        if (ac_file_dsc != -1)
        {
            int rc;
            do
            {
                rc = close(ac_file_dsc);
            }
            while (rc != 0 && errno == EINTR);
        }
    }

    // Processes requests read from standard input
    //
    // @throws std::bad_alloc, AnnotatedException
    int run(const uint16_t packet_count)
    {
        std::unique_ptr<char[]> line_buffer_mgr(new char[static_cast<size_t> (LINE_BUFFER_SIZE)]);
        char* const line_buffer = line_buffer_mgr.get();

        bool stream_good = false;

        std::unique_ptr<ipv4_packet> ipv4_packet_mgr;
        std::unique_ptr<ipv6_packet> ipv6_packet_mgr;

        std::unique_ptr<struct sockaddr_in> ipv4_src_address_mgr;
        std::unique_ptr<struct sockaddr_in> ipv4_dst_address_mgr;

        std::unique_ptr<struct sockaddr_in6> ipv6_src_address_mgr;
        std::unique_ptr<struct sockaddr_in6> ipv6_dst_address_mgr;

        std::string src_address_str;
        std::string src_netif_str;
        std::string src_port_str;

        std::string dst_address_str;
        std::string dst_port_str;

        int rc = ERR_GENERIC;
        do
        {
            try
            {
                std::cin.getline(line_buffer, LINE_BUFFER_SIZE);
                stream_good = std::cin.good();
                if (stream_good)
                {
                    // Get line_length without the trailing \0 character
                    const std::streamsize line_length = std::cin.gcount() - 1;
                    std::string address_pair(line_buffer, line_length);
                    // Trim leading and trailing space or tab characters
                    trim_lead(address_pair);
                    trim_trail(address_pair);

                    // Split at first space or tab character
                    const size_t split_idx = std::min(
                        address_pair.find(' '),
                        address_pair.find('\t')
                    );
                    if (split_idx != std::string::npos)
                    {
                        bool ipv6_flag = false;

                        // Split source address & port
                        {
                            std::string src_endpoint(address_pair, 0, split_idx);
                            split_address_and_port(src_endpoint, src_address_str, src_port_str);
                            ipv6_flag = src_address_str.find(':') != std::string::npos;
                        }

                        // Split destination address & port
                        {
                            std::string dst_endpoint(address_pair, split_idx + 1);
                            // Trim any further space or tab characters between
                            // the two addresses
                            trim_lead(dst_address_str);
                            split_address_and_port(dst_endpoint, dst_address_str, dst_port_str);
                        }

                        if (ipv6_flag)
                        {
                            // Split address and link-local zone (network interface name)
                            split_address_and_netif(src_address_str, src_netif_str);

                            // Dynamically allocate IPv6 data structures if not already allocated
                            if (ipv6_packet_mgr == nullptr)
                            {
                                ipv6_packet_mgr = std::unique_ptr<ipv6_packet>(new ipv6_packet);
                                ipv6_src_address_mgr = std::unique_ptr<struct sockaddr_in6>(new struct sockaddr_in6);
                                ipv6_dst_address_mgr = std::unique_ptr<struct sockaddr_in6>(new struct sockaddr_in6);
                            }

                            // Parse source address
                            parse_ipv6(src_address_str, &src_netif_str, src_port_str, *ipv6_src_address_mgr);
                            // Parse destination address
                            parse_ipv6(dst_address_str, nullptr, dst_port_str, *ipv6_dst_address_mgr);

                            send_ipv6_packet(
                                *ipv6_packet_mgr,
                                *ipv6_src_address_mgr,
                                *ipv6_dst_address_mgr,
                                packet_count
                            );
                        }
                        else
                        {
                            // Dynamically allocate IPv4 data structures if not already allocated
                            if (ipv4_packet_mgr == nullptr)
                            {
                                ipv4_packet_mgr = std::unique_ptr<ipv4_packet>(new ipv4_packet);
                                ipv4_src_address_mgr = std::unique_ptr<struct sockaddr_in>(new struct sockaddr_in);
                                ipv4_dst_address_mgr = std::unique_ptr<struct sockaddr_in>(new struct sockaddr_in);
                            }

                            parse_ipv4(src_address_str, src_port_str, *ipv4_src_address_mgr);
                            parse_ipv4(dst_address_str, dst_port_str, *ipv4_dst_address_mgr);

                            send_ipv4_packet(
                                *ipv4_packet_mgr,
                                *ipv4_src_address_mgr,
                                *ipv4_dst_address_mgr,
                                packet_count
                            );
                        }
                    }
                    else
                    {
                        std::cerr << "Warning: Ignored invalid input line" << std::endl;
                    }
                }
                else
                if (std::cin.eof())
                {
                    rc = EXIT_SUCCESS;
                }
                else
                {
                    rc = ERR_IO;
                    throw AnnotatedException(EIO, ERRMSG_STDIN_IO);
                }
            }
            catch (AnnotatedException& exc)
            {
                std::cerr << "Error: " << exc.what() << std::endl;
                display_error_nr_msg(exc.get_error_nr());
            }

            src_address_str.clear();
            src_port_str.clear();
            dst_address_str.clear();
            dst_port_str.clear();
        }
        while (stream_good);

        return rc;
    }

    // Displays information about the application's command line arguments
    void display_help() noexcept
    {
        std::cout << "Syntax: tickle_tcp [ -n <packet_count ]" << std::endl;
    }

    // Displays the system's description for an error code received from system functions
    void display_error_nr_msg(const int error_nr) noexcept
    {
        if (error_nr != 0)
        {
            const char* const errno_msg = strerror(error_nr);
            if (errno_msg != nullptr)
            {
                std::cerr << "    Error description: " << errno_msg << std::endl;
                std::cerr << "    Error code: " << error_nr << std::endl;
            }
        }
    }

    // Parses the command line arguments for this application
    //
    // @throws std::bad_alloc, AnnotatedException
    bool parse_arguments(const int argc, char* argv[], uint16_t& packet_count)
    {
        bool rc = true;
        if (argv != nullptr)
        {
            const std::string* crt_key = nullptr;

            for (int idx = 1; idx < argc; ++idx)
            {
                if (crt_key == nullptr)
                {
                    if (OPT_PACKET_COUNT == argv[idx])
                    {
                        crt_key = &OPT_PACKET_COUNT;
                    }
                    else
                    if (OPT_HELP == argv[idx] || LONG_OPT_HELP == argv[idx])
                    {
                        display_help();
                        rc = false;
                        break;
                    }
                    else
                    {
                        std::cerr << "Invalid command line argument '" << argv[idx] << "'" << std::endl;
                        display_help();
                        rc = false;
                        break;
                    }
                }
                else
                {
                    if (crt_key == &OPT_PACKET_COUNT)
                    {
                        std::string number(argv[idx]);
                        packet_count = parse_uint16(number);
                    }
                    crt_key = nullptr;
                }
            }
        }
        return rc;
    }

    // Splits the referenced address_and_port string into a separate address string and port string
    //
    // The port is expected to be the part of the string following the last occurence of the separator character ":".
    //
    // @throws std::bad_alloc, AnnotatedException
    void split_address_and_port(const std::string& address_and_port, std::string& address, std::string& port)
    {
        const size_t split_idx = address_and_port.rfind(':');
        if (split_idx != std::string::npos)
        {
            address = address_and_port.substr(0, split_idx);
            port = address_and_port.substr(split_idx + 1);
        }
        else
        {
            throw AnnotatedException(0, ERRMSG_UNPARSABLE_ENDPOINT);
        }
    }

    // Splits the referenced strings into an address and network interface part
    //
    // This applies to the string representation of link-local IPv6 addresses.
    // The format is: address%interface.
    // Input is expected in the address string. If a network interface suffix is present, the separator character
    // "%" and the interface name are removed from the address string, and the interface name is placed into
    // the netif string.
    //
    // @throws std::bad_alloc, AnnotatedException
    void split_address_and_netif(std::string& address, std::string& netif)
    {
        const size_t split_idx = address.rfind("%");
        if (split_idx != std::string::npos)
        {
            netif = address.substr(split_idx + 1);
            address = address.substr(0, split_idx);
        }
    }

    // Removes leading space and tab characters from the referenced string
    //
    // @throws std::bad_alloc
    void trim_lead(std::string& text)
    {
        const char* const data = text.c_str();
        const size_t data_length = text.length();

        for (size_t idx = 0; idx < data_length; ++idx)
        {
            if (data[idx] != ' ' && data[idx] != '\t')
            {
                text = text.substr(idx);
                break;
            }
        }
    }

    // Removes trailing space and tab characters from the referenced string
    //
    // @throws std::bad_alloc
    void trim_trail(std::string& text)
    {
        const char* const data = text.c_str();
        const size_t data_length = text.length();

        size_t idx = data_length;
        while (idx > 0)
        {
            --idx;
            if (data[idx] != ' ' && data[idx] != '\t')
            {
                text = text.substr(0, idx + 1);
                break;
            }
        }
    }

    // Parses the string representation of unsigned decimal integer numbers with a width of at most 16 bits
    //
    // @throws std::bad_alloc, AnnotatedException
    uint16_t parse_uint16(const std::string& number)
    {
        // Not using strtol/strtoll/etc. due to the various shortcomings of those functions,
        // such as allowing whitespace or allowing to parse negative numbers
        // as unsigned values.
        //
        // Derived from the integerparse module of the
        // C++ DSA library at https://github.com/raltnoeder/cppdsaext
        const size_t number_length = number.length();
        if (number_length < 1)
        {
            throw AnnotatedException(0, ERRMSG_INVALID_NR);
        }

        const uint16_t max_value_base = UINT16_MAX / 10;
        uint16_t result = 0;
        for (size_t index = 0; index < number_length; ++index)
        {
            if (result > max_value_base)
            {
                throw AnnotatedException(0, ERRMSG_INVALID_NR);
            }
            result *= 10;

            const unsigned char digit_char = static_cast<const unsigned char> (number[index]);
            if (!(digit_char >= '0' && digit_char <= '9'))
            {
                throw AnnotatedException(0, ERRMSG_INVALID_NR);
            }
            const uint16_t digit_value = digit_char - static_cast<const unsigned char> ('0');
            if (digit_value > UINT16_MAX - result)
            {
                throw AnnotatedException(0, ERRMSG_INVALID_NR);
            }
            result += digit_value;
        }

        return result;
    }

    // Parses the string representation of a port number
    //
    // @throws std::bad_alloc, AnnotatedException
    uint16_t parse_port_number(const std::string& number)
    {
        uint16_t value = 0;
        try
        {
            value = parse_uint16(number);
        }
        catch (AnnotatedException& exc)
        {
            throw AnnotatedException(0, ERRMSG_INVALID_PORT_NR);
        }
        return value;
    }

    // Parses the string representatio of an IPv4 address and port combination and applies the result
    // to a sockaddr_in data structure
    //
    // @throws std::bad_alloc, AnnotatedException
    void parse_ipv4(
        const std::string&  address_input,
        const std::string&  port_input,
        struct sockaddr_in& address
    )
    {
        const uint16_t port_number = parse_port_number(port_input);
        errno = 0;
        int rc = inet_pton(AF_INET, address_input.c_str(), &(address.sin_addr));
        check_inet_pton_rc(rc, errno);

        address.sin_family = AF_INET;
        address.sin_port = htons(port_number);
    }

    // Parses the string representation of an IPv6 address and port combination and applies the result
    // to a sockaddr_in6 data structure
    //
    // @throws std::bad_alloc, AnnotatedException
    void parse_ipv6(
        const std::string&          address_input,
        const std::string* const    netif_input,
        const std::string&          port_input,
        struct sockaddr_in6&        address
    )
    {
        const uint16_t port_number = parse_port_number(port_input);
        errno = 0;
        int rc = inet_pton(AF_INET6, address_input.c_str(), &(address.sin6_addr));
        check_inet_pton_rc(rc, errno);

        address.sin6_family = AF_INET6;
        address.sin6_port = htons(port_number);
        address.sin6_flowinfo = 0;
        address.sin6_scope_id = 0;

        if (IN6_IS_ADDR_LINKLOCAL(&(address.sin6_addr)) != 0)
        {
            if (netif_input != nullptr)
            {
                // There should be an IPv6 zone ID specified for this link-local address
                if (netif_input->length() >= 1)
                {
                    const unsigned int netif_index = if_nametoindex(netif_input->c_str());
                    if (netif_index != 0)
                    {
                        address.sin6_scope_id = static_cast<uint32_t> (netif_index);
                    }
                    else
                    {
                        // Invalid IPv6 zone ID
                        std::string error_msg(ERRMSG_LINKLOCAL_NO_NETIF);
                        error_msg += " \"";
                        error_msg += *netif_input;
                        error_msg += "\"";
                        throw AnnotatedException(errno, error_msg);
                    }
                }
                else
                {
                    // Required IPv6 zone ID not present
                    throw AnnotatedException(0, ERRMSG_UNUSABLE_LINKLOCAL);
                }
            }
            // else no IPv6 zone ID is required (e.g. it's a destination address)
        }
    }

    // Creates an IPv4 packet and sends it to the specified destination by calling send_packet
    //
    // @throws std::bad_alloc, AnnotatedException
    void send_ipv4_packet(
        ipv4_packet&        packet,
        const sockaddr_in&  src_address,
        const sockaddr_in&  dst_address,
        const uint16_t      packet_count
    )
    {
        std::memset(static_cast<void*> (&packet), 0, sizeof (packet));

        ipv4_header_no_opt& ip_header = packet.ip_header;
        ip_header.vsn_length    = sizeof (ipv4_header_no_opt) / sizeof (uint32_t);
        ip_header.vsn_length    |= 0x40;
        ip_header.length        = htons(sizeof (ipv4_header_no_opt) + sizeof (proto_tcp_header));
        ip_header.ttl           = 255;
        ip_header.protocol      = IPPROTO_TCP;
        ip_header.src_address   = src_address.sin_addr;
        ip_header.dst_address   = dst_address.sin_addr;
        ip_header.chksum        = 0;

        proto_tcp_header& tcp_header = packet.tcp_header;
        tcp_header.src_port         = src_address.sin_port;
        tcp_header.dst_port         = dst_address.sin_port;
        tcp_header.tcp_flags        = TCP_ACK;
        tcp_header.cmb_data_off_ns  = (sizeof (tcp_header) / 4) << 4;
        tcp_header.window_size      = htons(1234);
        tcp_header.checksum         = ipv4_tcp_checksum(
            reinterpret_cast<const unsigned char*> (&tcp_header),
            sizeof (tcp_header),
            &packet.ip_header
        );

        send_packet(
            AF_INET,
            reinterpret_cast<const struct sockaddr*> (&dst_address),
            sizeof (dst_address),
            ntohs(static_cast<uint16_t> (dst_address.sin_port)),
            static_cast<void*> (&packet),
            sizeof (packet),
            packet_count
        );
    }

    // Creates an IPv6 packet and sends it to the specified destination by calling send_packet
    //
    // @throws std::bad_alloc, AnnotatedException
    void send_ipv6_packet(
        ipv6_packet&        packet,
        const sockaddr_in6& src_address,
        const sockaddr_in6& dst_address,
        const uint16_t      packet_count
    )
    {
        std::memset(static_cast<void*> (&packet), 0, sizeof (packet));

        ipv6_header& ip_header = packet.ip_header;
        ip_header.vsn_cls_flowlbl   = htons(0x6000);
        ip_header.hop_limit         = 64;
        ip_header.next_header       = IPPROTO_TCP;
        ip_header.length            = htons(20);
        memcpy(ip_header.src_address, &src_address.sin6_addr, sizeof (ip_header.src_address));
        memcpy(ip_header.dst_address, &dst_address.sin6_addr, sizeof (ip_header.dst_address));

        proto_tcp_header& tcp_header = packet.tcp_header;
        tcp_header.src_port         = src_address.sin6_port;
        tcp_header.dst_port         = dst_address.sin6_port;
        tcp_header.tcp_flags        = TCP_ACK;
        tcp_header.cmb_data_off_ns  = (sizeof (tcp_header) / 4) << 4;
        tcp_header.window_size      = htons(1234);
        tcp_header.checksum         = ipv6_tcp_checksum(
            reinterpret_cast<const unsigned char*> (&tcp_header),
            sizeof (tcp_header),
            &packet.ip_header
        );

        // Required for sending an IPv6 packet without generating an EINVAL error.
        // This behavior seems to be undocumented.
        std::unique_ptr<struct sockaddr_in6> send_dst_address_mgr(new struct sockaddr_in6);
        struct sockaddr_in6* const send_dst_address = send_dst_address_mgr.get();
        *send_dst_address = dst_address;
        send_dst_address->sin6_port = 0;

        send_packet(
            AF_INET6,
            reinterpret_cast<const struct sockaddr* const> (send_dst_address),
            sizeof (*send_dst_address),
            ntohs(static_cast<uint16_t> (dst_address.sin6_port)),
            static_cast<void*> (&packet),
            sizeof (packet),
            packet_count
        );
    }

    // Sends a packet to the specified destination address
    //
    // @throws std::bad_alloc, AnnotatedException
    void send_packet(
        const int                       socket_domain,
        const struct sockaddr* const    dst_address,
        const size_t                    dst_address_size,
        const uint16_t                  dst_port,
        const void* const               packet_data,
        const size_t                    packet_data_size,
        const uint16_t                  packet_count
    )
    {
        // Create a raw IP socket
        const int socket_dsc = socket(socket_domain, SOCK_RAW, IPPROTO_RAW);
        if (socket_dsc == -1)
        {
            throw AnnotatedException(errno, ERRMSG_SOCKET_RAW_FAIL);
        }
        // Close the socket when leaving scope
        AutoClose socket_guard(socket_dsc);

        // Make the socket non-blocking
        set_fcntl_flags(socket_dsc, O_NONBLOCK);

        // Change socket options for inclusion of the custom IP header
        if (socket_domain == AF_INET)
        {
            const uint32_t sockopt_value = 1;
            if (setsockopt(socket_dsc, SOL_IP, IP_HDRINCL, &sockopt_value, sizeof (sockopt_value)) != 0)
            {
                throw AnnotatedException(errno, ERRMSG_SETSOCKOPT_FAIL);
            }
        }

        for (uint16_t counter = 0; counter < packet_count; ++counter)
        {
            // Send the packet. This is supposed to either send the entire packet or send nothing and fail,
            // returning -1. I/O errors generate a warning but are otherwise ignored, so the program can
            // continue sending packets to other destinations.
            const ssize_t write_count = sendto(
                socket_dsc,
                packet_data,
                packet_data_size,
                0,
                dst_address,
                dst_address_size
            );
            if (write_count == -1)
            {
                const int send_error_code = errno;
                const void* dst_ip = nullptr;
                std::unique_ptr<char[]> dst_address_str(new char[ADDRESS_BUFFER_SIZE]);
                if (socket_domain == AF_INET6)
                {
                    const struct sockaddr_in6* const ipv6_dst_address =
                        reinterpret_cast<const struct sockaddr_in6* const> (dst_address);
                    dst_ip = static_cast<const void*> (&ipv6_dst_address->sin6_addr);
                }
                else
                {
                    const struct sockaddr_in* const ipv4_dst_address =
                        reinterpret_cast<const struct sockaddr_in* const> (dst_address);
                    dst_ip = static_cast<const void*> (&ipv4_dst_address->sin_addr);
                }
                const char* const ntop_rc = inet_ntop(
                    socket_domain,
                    dst_ip,
                    dst_address_str.get(),
                    ADDRESS_BUFFER_SIZE
                );
                if (ntop_rc != nullptr)
                {
                    std::cerr << "Warning: Sending a packet to destination " << dst_address_str.get() <<
                        ":" << dst_port << " failed" <<
                        std::endl;
                    display_error_nr_msg(send_error_code);
                }
                else
                {
                    const int ntop_error_code = errno;
                    std::cerr << "Warning: Sending a packet failed\n";
                    display_error_nr_msg(send_error_code);
                    std::cerr << "Warning: Failed to generate a string representation of the destination address" <<
                        std::endl;
                    display_error_nr_msg(ntop_error_code);
                }
            }
        }
    }

    // Checks the result of an inet_pton call and throws an AnnotatedException describing the problem
    // if the inet_pton call was not successful
    //
    // @throws std::bad_alloc, AnnotatedException
    void check_inet_pton_rc(const int rc, const int error_nr)
    {
        switch (rc)
        {
            case 0:
            {
                // Invalid address string
                throw AnnotatedException(error_nr, ERRMSG_INVALID_IP_ADDRESS);
                break;
            }
            case 1:
            {
                // Successful sockaddr initialization
                break;
            }
            case -1:
            {
                // Unsupported address family
                throw AnnotatedException(error_nr, ERRMSG_INVALID_ADDR_FAM);
                break;
            }
            default:
            {
                // Undocumented return code
                throw AnnotatedException(
                    error_nr,
                    ERRMSG_INET_PTON_FAIL
                );
                break;
            }
        }
    }

    // Sets flags on a file descriptor
    //
    // @throws std::bad_alloc, AnnotatedException
    void set_fcntl_flags(const int file_dsc, const int flags)
    {
        const int current_flags = fcntl(file_dsc, F_GETFL, 0);
        if (current_flags != -1)
        {
            if (fcntl(file_dsc, F_SETFL, current_flags | flags) != 0)
            {
                throw application::AnnotatedException(errno, application::ERRMSG_FCNTL_FAIL);
            }
        }
        else
        {
            throw application::AnnotatedException(errno, application::ERRMSG_FCNTL_FAIL);
        }
    }

    // Calculates an IPv4 packet's TCP checksum
    uint16_t ipv4_tcp_checksum(
        const unsigned char* const      data,
        const size_t                    length,
        const ipv4_header_no_opt* const header
    ) noexcept
    {
        uint32_t native_sum = checksum(data, length);
        native_sum += checksum(
            reinterpret_cast<const unsigned char*> (&header->src_address), sizeof (header->src_address)
        );
        native_sum += checksum(
            reinterpret_cast<const unsigned char*> (&header->dst_address), sizeof (header->dst_address)
        );
        native_sum += header->protocol + static_cast<uint32_t> (length);
        // Rotate / add twice
        native_sum = (native_sum & 0xFFFF) + (native_sum >> 16);
        native_sum = (native_sum & 0xFFFF) + (native_sum >> 16);

        uint16_t network_sum = htons(static_cast<uint16_t> (native_sum));
        // Invert checksum
        network_sum = ~network_sum;
        if (network_sum == 0)
        {
            network_sum = 0xFFFF;
        }
        return network_sum;
    }

    // Calculates an IPv6 packet's TCP checksum
    uint16_t ipv6_tcp_checksum(
        const unsigned char* const  data,
        const size_t                length,
        const ipv6_header* const    header
    ) noexcept
    {
        uint32_t native_sum = 0;
        native_sum += checksum(reinterpret_cast<const unsigned char*> (&header->src_address), 16);
        native_sum += checksum(reinterpret_cast<const unsigned char*> (&header->dst_address), 16);

        {
            uint32_t proto_header[2];
            proto_header[0] = htonl(length);
            proto_header[1] = htonl(header->next_header);
            native_sum += checksum(reinterpret_cast<const unsigned char*> (&proto_header[0]), sizeof (proto_header));
        }

        native_sum += checksum(data, length);

        // Rotate / add twice
        native_sum = (native_sum & 0xFFFF) + (native_sum >> 16);
        native_sum = (native_sum & 0xFFFF) + (native_sum >> 16);

        uint16_t network_sum = htons(native_sum);
        // Invert checksum
        network_sum = ~network_sum;
        if (network_sum == 0)
        {
            network_sum = 0xFFFF;
        }
        return network_sum;
    }

    uint32_t checksum(const unsigned char* const data, const size_t length) noexcept
    {
        uint32_t result = 0;
        for (size_t idx = 0; idx < length; ++idx)
        {
            result += (idx & 0x1) == 0 ? static_cast<uint16_t> (data[idx]) << 8 : static_cast<uint16_t> (data[idx]);
        }
        return result;
    }
}
