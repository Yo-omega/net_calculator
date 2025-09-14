#include "net.h"
#include "network_calcs.h"
#include "utils.h"
#include "display.h"
#include <math.h>

int parse_ip(const char *ip_str, uint32_t *ip_int) {
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) {
        return 0;
    }
    *ip_int = ntohl(addr.s_addr);
    return 1;
}

void format_ip(uint32_t ip_int, char *ip_str, size_t ip_str_len) {
    struct in_addr addr;
    addr.s_addr = htonl(ip_int);
    const char *ip = inet_ntoa(addr);
    if (ip) {
        strncpy(ip_str, ip, ip_str_len - 1);
        ip_str[ip_str_len - 1] = '\0';
    } else {
        ip_str[0] = '\0';
    }
}

uint32_t cidr_to_mask(int prefix_length) {
    if (prefix_length < 0 || prefix_length > 32) {
        return 0;
    }
    if (prefix_length == 0) {
        return 0;
    }
    return 0xFFFFFFFF << (32 - prefix_length);
}

int mask_to_cidr(uint32_t mask) {
    int prefix_length = 0;
    int seen_zero = 0;
    for (int i = 31; i >= 0; i--) {
        if ((mask >> i) & 1) {
            if (seen_zero) {
                return -1; // Non-contiguous mask
            }
            prefix_length++;
        } else {
            seen_zero = 1;
        }
    }
    return prefix_length;
}

int parse_cidr(const char *input) {
    char *endptr;
    long cidr;

    const char *start = (input[0] == '/') ? input + 1 : input;
    
    cidr = strtol(start, &endptr, 10);

    if (*endptr != '\0' || cidr < 0 || cidr > 32) {
        return -1;
    }
    
    return (int)cidr;
}

int parse_ip_network(const char *input, uint32_t *ip, int *prefix_len) {
    char input_copy[MAX_INPUT];
    char *space_pos, *slash_pos;
    
    strncpy(input_copy, input, sizeof(input_copy) - 1);
    input_copy[sizeof(input_copy) - 1] = '\0';

    space_pos = strchr(input_copy, ' ');
    if (space_pos) {
        *space_pos = '\0';
        char *mask_str = space_pos + 1;
        
        while (*mask_str == ' ') mask_str++;
        
        if (!parse_ip(input_copy, ip)) {
            return 0;
        }
        
        uint32_t mask;
        if (parse_ip(mask_str, &mask)) {
            *prefix_len = mask_to_cidr(mask);
            return (*prefix_len != -1);
        } else {
            *prefix_len = parse_cidr(mask_str);
            return (*prefix_len != -1);
        }
    }
    
    slash_pos = strchr(input_copy, '/');
    if (slash_pos) {
        *slash_pos = '\0';
        
        if (!parse_ip(input_copy, ip)) {
            return 0;
        }
        
        *prefix_len = parse_cidr(slash_pos + 1);
        return (*prefix_len != -1);
    }
    
    if (parse_ip(input_copy, ip)) {
        *prefix_len = 32;
        return 1;
    }
    
    return 0;
}

int calculate_network_info(uint32_t ip, int prefix_len, network_info_t *info) {
    if (prefix_len < 0 || prefix_len > 32) {
        return 0;
    }
    
    info->prefix_length = prefix_len;
    info->subnet_mask = cidr_to_mask(prefix_len);
    info->network_address = ip & info->subnet_mask;
    
    if (prefix_len == 32) {
        info->broadcast_address = info->network_address;
        info->first_host_address = 0;
        info->last_host_address = 0;
        info->host_count = 0;
    } else if (prefix_len == 31) {
        info->broadcast_address = info->network_address + 1;
        info->first_host_address = info->network_address;
        info->last_host_address = info->network_address + 1;
        info->host_count = 2;
    } else {
        uint32_t host_mask = ~info->subnet_mask;
        info->broadcast_address = info->network_address | host_mask;
        info->first_host_address = info->network_address + 1;
        info->last_host_address = info->broadcast_address - 1;
        info->host_count = (1U << (32 - prefix_len)) - 2;
    }
    
    return 1;
}

void lazy_mode(const char *input) {
    uint32_t ip;
    int prefix_len;
    network_info_t info;
    
    if (!parse_ip_network(input, &ip, &prefix_len)) {
        print_error("Invalid input format.");
        print_info("Supported formats:");
        printf("  • IP/CIDR: 192.168.1.10/24\n");
        printf("  • IP MASK: 192.168.1.10 255.255.255.0\n");
        printf("  • IP CIDR: 192.168.1.10 24\n");
        printf("  • Just IP: 192.168.1.10 (assumes /32)\n");
        return;
    }
    
    if (!calculate_network_info(ip, prefix_len, &info)) {
        print_error("Invalid network parameters");
        return;
    }
    
    display_network_analysis(&info);
}

void bitwise_and_operation(const char *ip_str, const char *mask_input) {
    uint32_t ip, mask, result;
    char result_str[INET_ADDRSTRLEN];
    
    if (!parse_ip(ip_str, &ip)) {
        print_error("Invalid IP address format");
        return;
    }
    
    if (parse_ip(mask_input, &mask)){}
	else {
        int cidr = parse_cidr(mask_input);
        if (cidr == -1) {
            print_error("Invalid subnet mask or CIDR format");
            return;
        }
        mask = cidr_to_mask(cidr);
    }
    
    result = ip & mask;
    format_ip(result, result_str, sizeof(result_str));
    
    print_color(ANSI_STYLE_BOLD, "Network Address: ");
    print_color(ANSI_COLOR_GREEN, "%s", result_str);
    printf("\n");
}

void decimal_to_binary(int octet) {
    if (octet < 0 || octet > 255) {
        print_error("Invalid octet (must be 0-255)");
        return;
    }
    
    print_color(ANSI_STYLE_BOLD, "Decimal: ");
    print_color(ANSI_COLOR_CYAN, "%d", octet);
    printf("\n");
    
    print_color(ANSI_STYLE_BOLD, "Binary: ");
    print_color(ANSI_COLOR_GREEN, "");
    for (int i = 7; i >= 0; i--) {
        printf("%d", (octet >> i) & 1);
        if (i == 4) printf(" ");
    }
    printf("%s", ANSI_COLOR_RESET);
    printf("\n");
    
    print_color(ANSI_STYLE_BOLD, "Hex: ");
    print_color(ANSI_COLOR_YELLOW, "0x%02X", octet);
    printf("\n");
}

void binary_to_decimal(const char *binary_input) {
    char binary[9];
    int len = strlen(binary_input);

    int j = 0;
    for (int i = 0; i < len && j < 8; i++) {
        if (binary_input[i] == '0' || binary_input[i] == '1') {
            binary[j++] = binary_input[i];
        } else if (binary_input[i] != ' ' && binary_input[i] != '.') {
            print_error("Invalid binary (only 0, 1, spaces, and dots allowed)");
            return;
        }
    }
    binary[j] = '\0';
    
    if (j != 8) {
        print_error("Invalid binary (must be exactly 8 bits)");
        return;
    }
    
    int decimal = 0;
    for (int i = 0; i < 8; i++) {
        decimal = decimal * 2 + (binary[i] - '0');
    }
    
    print_color(ANSI_STYLE_BOLD, "Binary: ");
    print_color(ANSI_COLOR_GREEN, "%.4s %.4s", binary, binary + 4);
    printf("\n");
    
    print_color(ANSI_STYLE_BOLD, "Decimal: ");
    print_color(ANSI_COLOR_CYAN, "%d", decimal);
    printf("\n");
    
    print_color(ANSI_STYLE_BOLD, "Hex: ");
    print_color(ANSI_COLOR_YELLOW, "0x%02X", decimal);
    printf("\n");
}

void cidr_to_binary_mask(const char *cidr_input) {
    int cidr = parse_cidr(cidr_input);
    
    if (cidr == -1) {
        print_error("Invalid CIDR (must be 0-32, with or without '/')");
        return;
    }
    
    uint32_t mask = cidr_to_mask(cidr);
    char mask_str[INET_ADDRSTRLEN];
    format_ip(mask, mask_str, sizeof(mask_str));
    
    print_color(ANSI_STYLE_BOLD, "CIDR: ");
    print_color(ANSI_COLOR_CYAN, "/%d", cidr);
    printf("\n");
    
    print_color(ANSI_STYLE_BOLD, "Decimal Mask: ");
    print_color(ANSI_COLOR_GREEN, "%s", mask_str);
    printf("\n");
    
    print_color(ANSI_STYLE_BOLD, "Binary Mask: ");
    char binary_mask[40];
    format_binary(mask, binary_mask, sizeof(binary_mask));
    print_color(ANSI_COLOR_YELLOW, "%s", binary_mask);
    printf("\n");
    
    print_color(ANSI_STYLE_BOLD, "Hex Mask: ");
    print_color(ANSI_COLOR_MAGENTA, "0x%08X", mask);
    printf("\n");
}

void subnetting(const char *network_str, const char *new_cidr_str) {
    uint32_t network_ip;
    int original_cidr, new_cidr;
    
    if (!parse_ip_network(network_str, &network_ip, &original_cidr)) {
        print_error("Invalid network format");
        return;
    }
    
    new_cidr = parse_cidr(new_cidr_str);
    if (new_cidr == -1) {
        print_error("Invalid new CIDR format");
        return;
    }
    
    if (new_cidr <= original_cidr) {
        print_error("New CIDR must be larger than current CIDR");
        printf("Current: /%d, Requested: /%d\n", original_cidr, new_cidr);
        return;
    }
    
    if (new_cidr > 32) {
        print_error("CIDR cannot be larger than 32");
        return;
    }
    
    uint32_t subnet_mask = cidr_to_mask(original_cidr);
    uint32_t network_addr = network_ip & subnet_mask;
    
    int subnet_bits = new_cidr - original_cidr;
    int num_subnets = 1 << subnet_bits;
    uint32_t subnet_size = (new_cidr == 32) ? 1 : (1U << (32 - new_cidr));
    
    print_header("=== Subnetting Results ===");
    print_color(ANSI_STYLE_BOLD, "Original Network: ");
    char orig_ip[INET_ADDRSTRLEN];
    format_ip(network_addr, orig_ip, sizeof(orig_ip));
    print_color(ANSI_COLOR_CYAN, "%s/%d", orig_ip, original_cidr);
    printf("\n");
    
    print_color(ANSI_STYLE_BOLD, "New Subnet Size: ");
    print_color(ANSI_COLOR_YELLOW, "/%d", new_cidr);
    printf("\n");
    
    print_color(ANSI_STYLE_BOLD, "Number of Subnets: ");
    print_color(ANSI_COLOR_MAGENTA, "%d", num_subnets);
    printf("\n");
    
    print_separator();
    
    printf("%-20s %-15s %-15s %-10s\n", "Subnet", "First Host", "Last Host", "Hosts");
    printf("%-20s %-15s %-15s %-10s\n", "--------------------", "---------------", "---------------", "----------");
    
    for (int i = 0; i < num_subnets && i < MAX_SUBNETS; i++) {
        uint32_t subnet_addr = network_addr + (uint64_t)i * subnet_size;
        network_info_t subnet_info;
        
        if (calculate_network_info(subnet_addr, new_cidr, &subnet_info)) {
            char subnet_ip[INET_ADDRSTRLEN], first_host[INET_ADDRSTRLEN], last_host[INET_ADDRSTRLEN];
            
            format_ip(subnet_info.network_address, subnet_ip, sizeof(subnet_ip));
            
            if (subnet_info.host_count > 0) {
                format_ip(subnet_info.first_host_address, first_host, sizeof(first_host));
                format_ip(subnet_info.last_host_address, last_host, sizeof(last_host));
                printf("%-20s %-15s %-15s %-10d\n", 
                       subnet_ip, first_host, last_host, subnet_info.host_count);
            } else {
                printf("%-20s %-15s %-15s %-10s\n", 
                       subnet_ip, "N/A", "N/A", "0");
            }
        }
    }
    
    if (num_subnets > MAX_SUBNETS) {
        print_warning("Only showing first 1024 subnets");
    }
}

int validate_network_format(const char *network) {
    uint32_t ip;
    int prefix_len;
    return parse_ip_network(network, &ip, &prefix_len);
}

void generate_routing_table(void) {
    char destinations[MAX_DESTINATIONS][MAX_INPUT];
    char next_hop[MAX_INPUT];
    char input_line[MAX_INPUT * 4];
    int dest_count = 0;
    
    print_header("=== Enhanced Routing Table Generator ===");
    print_info("Supported destination formats:");
    printf("  • CIDR: 192.168.1.0/24\n");
    printf("  • IP + Mask: 192.168.1.0 255.255.255.0\n");
    printf("  • IP + CIDR: 192.168.1.0 24\n");
    printf("  • Single IP: 192.168.1.1 (assumes /32)\n");
    printf("\n");
    
    print_color(ANSI_STYLE_BOLD, "Enter destination networks ");
    print_color(ANSI_COLOR_CYAN, "(separate with spaces or commas):\n");
    printf("Destinations: ");
    
    if (!safe_input(input_line, sizeof(input_line))) {
        print_error("Input error");
        return;
    }
    
    char *token = strtok(input_line, " ,");
    while (token != NULL && dest_count < MAX_DESTINATIONS) {
        if (strlen(token) > 0 && strlen(token) < MAX_INPUT) {
            strncpy(destinations[dest_count], token, MAX_INPUT - 1);
            destinations[dest_count][MAX_INPUT - 1] = '\0';
            dest_count++;
        }
        token = strtok(NULL, " ,");
    }
    
    if (dest_count == 0) {
        print_error("No valid destination networks provided");
        return;
    }
    
    print_color(ANSI_STYLE_BOLD, "Enter next-hop IP address: ");
    if (!safe_input(next_hop, sizeof(next_hop))) {
        print_error("Input error");
        return;
    }
    
    uint32_t next_hop_ip;
    if (!parse_ip(next_hop, &next_hop_ip)) {
        print_error("Invalid next-hop IP address");
        return;
    }
    
    print_separator();
    print_header("Generated Routing Table Entries");
    
    printf("%-25s %-15s %-15s\n", "Destination", "Next-Hop", "Status");
    printf("%-25s %-15s %-15s\n", "-------------------------", "---------------", "---------------");
    
    int valid_routes = 0;
    for (int i = 0; i < dest_count; i++) {
        uint32_t dest_ip;
        int prefix_len;
        if (parse_ip_network(destinations[i], &dest_ip, &prefix_len)) {
            char formatted_dest[MAX_INPUT];
            char dest_ip_str[INET_ADDRSTRLEN];
            format_ip(dest_ip & cidr_to_mask(prefix_len), dest_ip_str, sizeof(dest_ip_str));
            snprintf(formatted_dest, sizeof(formatted_dest), "%s/%d", dest_ip_str, prefix_len);
            
            printf("%-25s %-15s ", formatted_dest, next_hop);
            print_color(ANSI_COLOR_GREEN, "Valid");
            printf("\n");
            valid_routes++;
        } else {
            printf("%-25s %-15s ", destinations[i], next_hop);
            print_color(ANSI_COLOR_RED, "Invalid");
            printf("\n");
        }
    }
    
    printf("\n");
    print_color(ANSI_STYLE_BOLD, "Summary: ");
    print_color(ANSI_COLOR_GREEN, "%d", valid_routes);
    printf(" valid routes generated out of ");
    print_color(ANSI_COLOR_CYAN, "%d", dest_count);
    printf(" destinations\n");
    
    if (valid_routes > 0) {
        printf("\n");
        print_color(ANSI_STYLE_BOLD, "Export formats:\n");
        printf("1. Cisco IOS format\n");
        printf("2. Linux route format\n");
        printf("3. Simple format\n");
        printf("Choose export format (1-3, or Enter to skip): ");
        
        char export_choice[MAX_INPUT];
        if (safe_input(export_choice, sizeof(export_choice)) && strlen(export_choice) > 0) {
            int choice = atoi(export_choice);
            
            print_separator();
            print_header("Exported Routes");
            
            for (int i = 0; i < dest_count; i++) {
                uint32_t dest_ip;
                int prefix_len;
                if (validate_network_format(destinations[i])) {
                    parse_ip_network(destinations[i], &dest_ip, &prefix_len);
                    
                    char formatted_dest[MAX_INPUT];
                    char dest_ip_str[INET_ADDRSTRLEN];
                    format_ip(dest_ip & cidr_to_mask(prefix_len), dest_ip_str, sizeof(dest_ip_str));
                    
                    switch (choice) {
                        case 1: // Cisco
                            {
                                char mask_str[INET_ADDRSTRLEN];
                                format_ip(cidr_to_mask(prefix_len), mask_str, sizeof(mask_str));
                                print_color(ANSI_COLOR_YELLOW, "ip route %s %s %s", dest_ip_str, mask_str, next_hop);
                            }
                            printf("\n");
                            break;
                        case 2: // Linux
                            snprintf(formatted_dest, sizeof(formatted_dest), "%s/%d", dest_ip_str, prefix_len);
                            print_color(ANSI_COLOR_YELLOW, "ip route add %s via %s", formatted_dest, next_hop);
                            printf("\n");
                            break;
                        case 3: // Simple
                        default:
                            snprintf(formatted_dest, sizeof(formatted_dest), "%s/%d", dest_ip_str, prefix_len);
                            print_color(ANSI_COLOR_YELLOW, "%s => %s", formatted_dest, next_hop);
                            printf("\n");
                            break;
                    }
                }
            }
        }
    }
}

void format_binary(uint32_t num, char* out_str, size_t out_len) {
    if (out_len == 0) return;
    size_t pos = 0;
    for (int i = 31; i >= 0 && pos < out_len - 1; i--) {
        out_str[pos++] = ((num >> i) & 1) ? '1' : '0';
        if (i % 8 == 0 && i > 0 && pos < out_len - 1) {
            out_str[pos++] = '.';
        }
    }
    out_str[pos] = '\0';
}

// Comparison function for qsort
static int compare_hosts(const void *a, const void *b) {
    return (*(int*)b - *(int*)a);
}

static int hosts_to_prefix(int hosts) {
    if (hosts <= 0) return 32;
    // +2 for network and broadcast addresses
    int required_size = hosts + 2;
    int power_of_2 = 0;
    while ((1 << power_of_2) < required_size) {
        power_of_2++;
    }
    return 32 - power_of_2;
}

void vlsm_calculator(const char *base_network_str, const int *host_requirements, int num_subnets) {
    uint32_t base_ip;
    int base_prefix;

    if (!parse_ip_network(base_network_str, &base_ip, &base_prefix)) {
        print_error("Invalid base network format.");
        return;
    }

    // Create a mutable copy of host requirements for sorting
    int *sorted_hosts = malloc(num_subnets * sizeof(int));
    if (!sorted_hosts) {
        print_error("Memory allocation failed.");
        return;
    }
    memcpy(sorted_hosts, host_requirements, num_subnets * sizeof(int));
    qsort(sorted_hosts, num_subnets, sizeof(int), compare_hosts);

    print_header("=== VLSM Calculation Results ===");
    char base_net_str[INET_ADDRSTRLEN];
    format_ip(base_ip, base_net_str, sizeof(base_net_str));
    print_color(ANSI_STYLE_BOLD, "Base Network: %s/%d\n", base_net_str, base_prefix);
    print_separator();

    printf("%-12s %-18s %-18s %-15s %-10s\n", "Required", "Subnet Address", "Subnet Mask", "Host Range", "Hosts");
    printf("%-12s %-18s %-18s %-15s %-10s\n", "------------", "------------------", "------------------", "---------------", "----------");

    uint32_t current_ip = base_ip;
    uint32_t total_address_space = 1U << (32 - base_prefix);
    uint32_t used_address_space = 0;

    for (int i = 0; i < num_subnets; i++) {
        int required_hosts = sorted_hosts[i];
        int new_prefix = hosts_to_prefix(required_hosts);

        if (new_prefix < base_prefix) {
            char warning_msg[128];
            snprintf(warning_msg, sizeof(warning_msg), "Subnet for %d hosts requires a larger network than the base network.", required_hosts);
            print_warning(warning_msg);
            continue;
        }

        uint32_t subnet_size = 1U << (32 - new_prefix);
        used_address_space += subnet_size;

        if (used_address_space > total_address_space) {
            print_error("Not enough address space in the base network for all required subnets.");
            break;
        }
        
        network_info_t info;
        calculate_network_info(current_ip, new_prefix, &info);

        char subnet_addr_str[INET_ADDRSTRLEN];
        char subnet_mask_str[INET_ADDRSTRLEN];
        char first_host_str[INET_ADDRSTRLEN];
        char last_host_str[INET_ADDRSTRLEN];
        char host_range_str[40];

        format_ip(info.network_address, subnet_addr_str, sizeof(subnet_addr_str));
        format_ip(info.subnet_mask, subnet_mask_str, sizeof(subnet_mask_str));
        
        if (info.host_count > 0) {
            format_ip(info.first_host_address, first_host_str, sizeof(first_host_str));
            format_ip(info.last_host_address, last_host_str, sizeof(last_host_str));
            snprintf(host_range_str, sizeof(host_range_str), "%s - %s", first_host_str, last_host_str);
        } else {
            strcpy(host_range_str, "N/A");
        }

        printf("%-12d %-18s %-18s %-15s %-10u\n",
               required_hosts,
               subnet_addr_str,
               subnet_mask_str,
               host_range_str,
               info.host_count);

        current_ip += subnet_size;
    }

    free(sorted_hosts);
}

void find_best_subnet(int required_hosts) {
    if (required_hosts <= 0) {
        print_error("Number of hosts must be positive.");
        return;
    }

    int prefix = hosts_to_prefix(required_hosts);
    uint32_t mask = cidr_to_mask(prefix);
    uint32_t host_count = (1U << (32 - prefix)) - 2;

    char mask_str[INET_ADDRSTRLEN];
    format_ip(mask, mask_str, sizeof(mask_str));

    print_header("=== Best Subnet Suggestion ===");
    print_color(ANSI_STYLE_BOLD, "Required Hosts: ");
    print_color(ANSI_COLOR_CYAN, "%d\n", required_hosts);
    print_separator();
    print_color(ANSI_STYLE_BOLD, "Recommended CIDR: ");
    print_color(ANSI_COLOR_GREEN, "/%d\n", prefix);
    print_color(ANSI_STYLE_BOLD, "Subnet Mask: ");
    print_color(ANSI_COLOR_GREEN, "%s\n", mask_str);
    print_color(ANSI_STYLE_BOLD, "Available Hosts: ");
    print_color(ANSI_COLOR_GREEN, "%u\n", host_count);
    print_color(ANSI_STYLE_BOLD, "Wasted Hosts: ");
    print_color(ANSI_COLOR_YELLOW, "%u\n", host_count - required_hosts);
}
