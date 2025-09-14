#include "net.h"
#include "network_calcs.h"
#include "utils.h"

void display_network_analysis(const network_info_t* info) {
    char ip_str[INET_ADDRSTRLEN];

    print_header("=== Network Analysis ===");

    format_ip(info->network_address, ip_str, sizeof(ip_str));
    print_color(ANSI_STYLE_BOLD, "Network Address: ");
    print_color(ANSI_COLOR_GREEN, "%s", ip_str);
    printf("\n");

    format_ip(info->subnet_mask, ip_str, sizeof(ip_str));
    print_color(ANSI_STYLE_BOLD, "Subnet Mask:     ");
    print_color(ANSI_COLOR_GREEN, "%s", ip_str);
    printf(" ");
    print_color(ANSI_COLOR_CYAN, "(/%d)", info->prefix_length);
    printf("\n");

    format_ip(info->broadcast_address, ip_str, sizeof(ip_str));
    print_color(ANSI_STYLE_BOLD, "Broadcast Addr:  ");
    print_color(ANSI_COLOR_GREEN, "%s", ip_str);
    printf("\n");

    if (info->host_count > 0) {
        format_ip(info->first_host_address, ip_str, sizeof(ip_str));
        print_color(ANSI_STYLE_BOLD, "Host Range:      ");
        print_color(ANSI_COLOR_YELLOW, "%s", ip_str);
        printf(" - ");
        format_ip(info->last_host_address, ip_str, sizeof(ip_str));
        print_color(ANSI_COLOR_YELLOW, "%s", ip_str);
        printf("\n");
        print_color(ANSI_STYLE_BOLD, "Number of Hosts: ");
        print_color(ANSI_COLOR_MAGENTA, "%d", info->host_count);
        printf("\n");
    } else {
        print_color(ANSI_STYLE_BOLD, "Host Range:      ");
        print_color(ANSI_COLOR_RED, "N/A");
        printf("\n");
        print_color(ANSI_STYLE_BOLD, "Number of Hosts: ");
        print_color(ANSI_COLOR_MAGENTA, "0");
        printf("\n");
    }

    print_separator();
}

void print_usage(const char *prog_name) {
    print_header("Net Tool - Network Calculator");
    printf("Usage: %s [OPTIONS] [NETWORK]\n\n", prog_name);
    
    print_color(ANSI_STYLE_BOLD, "PRIMARY USAGE:\n");
    printf("  %s <NETWORK>              Analyze a network (e.g., 192.168.1.10/24)\n\n", prog_name);

    print_color(ANSI_STYLE_BOLD, "OPTIONS:\n");
    printf("  -a, --analyze <NETWORK>    Analyze a network\n");
    printf("  -s, --subnet <NETWORK> <NEW_CIDR> Subnet a network\n");
    printf("  -b, --and <IP> <MASK/CIDR> Perform bitwise AND operation\n");
    printf("  -d, --dec2bin <0-255>      Convert decimal octet to binary/hex\n");
    printf("  -B, --bin2dec <BINARY>     Convert binary octet to decimal/hex\n");
    printf("  -c, --cidr2mask <CIDR>     Convert CIDR to mask in various formats\n");
    printf("  -r, --route                Generate a routing table\n");
    printf("  -h, --help                 Show this help message\n");
    printf("  --no-color                 Disable color output\n\n");
    
    print_color(ANSI_STYLE_BOLD, "EXAMPLES:\n");
    printf("  %s 192.168.1.10/24\n", prog_name);
    printf("  %s --subnet 192.168.0.0/24 26\n", prog_name);
    printf("  %s --and 192.168.1.100 255.255.255.0\n", prog_name);
    printf("  %s --dec2bin 192\n", prog_name);

	print_color(ANSI_STYLE_BOLD, "\nCoded by Yo-omega (https://github.com/Yo-omega)\n");
}

void display_network_analysis_json(const network_info_t *info) {
    char network_address_str[INET_ADDRSTRLEN];
    char broadcast_address_str[INET_ADDRSTRLEN];
    char first_host_str[INET_ADDRSTRLEN];
    char last_host_str[INET_ADDRSTRLEN];
    char subnet_mask_str[INET_ADDRSTRLEN];

    format_ip(info->network_address, network_address_str, sizeof(network_address_str));
    format_ip(info->broadcast_address, broadcast_address_str, sizeof(broadcast_address_str));
    format_ip(info->first_host_address, first_host_str, sizeof(first_host_str));
    format_ip(info->last_host_address, last_host_str, sizeof(last_host_str));
    format_ip(info->subnet_mask, subnet_mask_str, sizeof(subnet_mask_str));

    printf("{\n");
    printf("  \"network_address\": \"%s\",\n", network_address_str);
    printf("  \"prefix_length\": %d,\n", info->prefix_length);
    printf("  \"subnet_mask\": \"%s\",\n", subnet_mask_str);
    printf("  \"broadcast_address\": \"%s\",\n", broadcast_address_str);
    if (info->host_count > 0) {
        printf("  \"first_host_address\": \"%s\",\n", first_host_str);
        printf("  \"last_host_address\": \"%s\",\n", last_host_str);
    } else {
        printf("  \"first_host_address\": null,\n");
        printf("  \"last_host_address\": null,\n");
    }
    printf("  \"host_count\": %u\n", info->host_count);
    printf("}\n");
}
