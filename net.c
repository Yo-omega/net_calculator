#include "net.h"

int use_colors = 1;

void print_color(const char* color, const char* format, ...) {
    va_list args;
    if (use_colors) {
        printf("%s", color);
    }
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    if (use_colors) {
        printf("%s", ANSI_COLOR_RESET);
    }
}

void print_error(const char* msg) {
    print_color(ANSI_COLOR_RED, "Error: ");
    printf("%s\n", msg);
}

void print_success(const char* msg) {
    print_color(ANSI_COLOR_GREEN, "Success: ");
    printf("%s\n", msg);
}

void print_warning(const char* msg) {
    print_color(ANSI_COLOR_YELLOW, "Warning: ");
    printf("%s\n", msg);
}

void print_info(const char* msg) {
    print_color(ANSI_COLOR_CYAN, "Info: ");
    printf("%s\n", msg);
}

void print_header(const char* text) {
    print_color(ANSI_STYLE_BOLD ANSI_COLOR_BLUE, text);
    printf("\n");
}

void print_separator(void) {
    print_color(ANSI_COLOR_BLUE, "================================================\n");
}

typedef struct {
    uint32_t network_address;
    uint32_t broadcast_address;
    uint32_t subnet_mask;
    uint32_t first_host_address;
    uint32_t last_host_address;
    int prefix_length;
    int host_count;
} network_info_t;

int safe_input(char *buffer, int size) {
    if (!fgets(buffer, size, stdin)) {
        return 0;
    }
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len-1] == '\n') {
        buffer[len-1] = '\0';
    }
    return 1;
}

int parse_ip(const char *ip_str, uint32_t *ip_int) {
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) {
        return 0;
    }
    *ip_int = ntohl(addr.s_addr);
    return 1;
}

void format_ip(uint32_t ip_int, char *ip_str) {
    struct in_addr addr;
    addr.s_addr = htonl(ip_int);
    strcpy(ip_str, inet_ntoa(addr));
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
    
    info->prefix_len = prefix_len;
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
    char ip_str[INET_ADDRSTRLEN];
    
    print_header("=== Network Analysis (Lazy Mode) ===");
    
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
    
    print_separator();
    
    format_ip(info.network_address, ip_str);
    print_color(COLOR_BOLD, "Network Address: ");
    print_color(COLOR_GREEN, "%s", ip_str);
    printf("\n");
    
    format_ip(info.subnet_mask, ip_str);
    print_color(COLOR_BOLD, "Subnet Mask: ");
    print_color(COLOR_GREEN, "%s", ip_str);
    printf(" ");
    print_color(COLOR_CYAN, "(/%d)", info.prefix_len);
    printf("\n");
	
	format_ip(info.broadcast_address, ip_str);
	print_color(COLOR_BOLD, "Broadcast Address: ");
	print_color(COLOR_GREEN, "%s", ip_str);
	printf("\n");
    
    if (info.host_count > 0) {
        format_ip(info.first_host_address, ip_str);
        print_color(COLOR_BOLD, "Host Range: ");
        print_color(COLOR_YELLOW, "%s", ip_str);
        printf(" - ");
        format_ip(info.last_host_address, ip_str);
        print_color(COLOR_YELLOW, "%s", ip_str);
        printf("\n");
        print_color(COLOR_BOLD, "Number of Hosts: ");
        print_color(COLOR_MAGENTA, "%d", info.host_count);
        printf("\n");
    } else if (prefix_len == 31) {
        format_ip(info.first_host_address, ip_str);
        print_color(COLOR_BOLD, "Host Range: ");
        print_color(COLOR_YELLOW, "%s", ip_str);
        printf(" - ");
        format_ip(info.last_host_address, ip_str);
        print_color(COLOR_YELLOW, ip_str);
        print_color(COLOR_CYAN, " (point-to-point)");
        printf("\n");
        print_color(COLOR_BOLD, "Number of Hosts: ");
        print_color(COLOR_MAGENTA, "2");
        printf("\n");
    } else {
        print_color(COLOR_BOLD, "Host Range: ");
        print_color(COLOR_RED, "No hosts (host route)");
        printf("\n");
        print_color(COLOR_BOLD, "Number of Hosts: ");
        print_color(COLOR_MAGENTA, "0");
        printf("\n");
    }
    
    print_separator();
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
    format_ip(result, result_str);
    
    print_color(COLOR_BOLD, "Network Address: ");
    print_color(COLOR_GREEN, "%s", result_str);
    printf("\n");
}

void decimal_to_binary(int octet) {
    if (octet < 0 || octet > 255) {
        print_error("Invalid octet (must be 0-255)");
        return;
    }
    
    print_color(COLOR_BOLD, "Decimal: ");
    print_color(COLOR_CYAN, "%d", octet);
    printf("\n");
    
    print_color(COLOR_BOLD, "Binary: ");
    print_color(COLOR_GREEN, "");
    for (int i = 7; i >= 0; i--) {
        printf("%d", (octet >> i) & 1);
        if (i == 4) printf(" ");
    }
    printf("%s", COLOR_RESET);
    printf("\n");
    
    print_color(COLOR_BOLD, "Hex: ");
    print_color(COLOR_YELLOW, "0x%02X", octet);
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
    
    print_color(COLOR_BOLD, "Binary: ");
    print_color(COLOR_GREEN, "%.4s %.4s", binary, binary + 4);
    printf("\n");
    
    print_color(COLOR_BOLD, "Decimal: ");
    print_color(COLOR_CYAN, "%d", decimal);
    printf("\n");
    
    print_color(COLOR_BOLD, "Hex: ");
    print_color(COLOR_YELLOW, "0x%02X", decimal);
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
    format_ip(mask, mask_str);
    
    print_color(COLOR_BOLD, "CIDR: ");
    print_color(COLOR_CYAN, "/%d", cidr);
    printf("\n");
    
    print_color(COLOR_BOLD, "Decimal Mask: ");
    print_color(COLOR_GREEN, "%s", mask_str);
    printf("\n");
    
    print_color(COLOR_BOLD, "Binary Mask: ");
    print_color(COLOR_YELLOW, "");
    for (int octet = 3; octet >= 0; octet--) {
        uint8_t byte = (mask >> (octet * 8)) & 0xFF;
        for (int bit = 7; bit >= 0; bit--) {
            printf("%d", (byte >> bit) & 1);
        }
        if (octet > 0) printf(".");
    }
    printf("%s", COLOR_RESET);
    printf("\n");
    
    print_color(COLOR_BOLD, "Hex Mask: ");
    print_color(COLOR_MAGENTA, "0x%08X", mask);
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
    uint32_t subnet_size = 1U << (32 - new_cidr);
    
    print_header("=== Subnetting Results ===");
    print_color(COLOR_BOLD, "Original Network: ");
    char orig_ip[INET_ADDRSTRLEN];
    format_ip(network_addr, orig_ip);
    print_color(COLOR_CYAN, "%s/%d", orig_ip, original_cidr);
    printf("\n");
    
    print_color(COLOR_BOLD, "New Subnet Size: ");
    print_color(COLOR_YELLOW, "/%d", new_cidr);
    printf("\n");
    
    print_color(COLOR_BOLD, "Number of Subnets: ");
    print_color(COLOR_MAGENTA, "%d", num_subnets);
    printf("\n");
    
    print_separator();
    
    printf("%-20s %-15s %-15s %-10s\n", "Subnet", "First Host", "Last Host", "Hosts");
    printf("%-20s %-15s %-15s %-10s\n", "--------------------", "---------------", "---------------", "----------");
    
    for (int i = 0; i < num_subnets && i < MAX_SUBNETS; i++) {
        uint32_t subnet_addr = network_addr + (i * subnet_size);
        network_info_t subnet_info;
        
        if (calculate_network_info(subnet_addr, new_cidr, &subnet_info)) {
            char subnet_ip[INET_ADDRSTRLEN], first_host[INET_ADDRSTRLEN], last_host[INET_ADDRSTRLEN];
            
            format_ip(subnet_info.network_address, subnet_ip);
            
            if (subnet_info.host_count > 0) {
                format_ip(subnet_info.first_host_address, first_host);
                format_ip(subnet_info.last_host_address, last_host);
                printf("%-20s/%-2d %-15s %-15s %-10d\n", 
                       subnet_ip, new_cidr, first_host, last_host, subnet_info.host_count);
            } else {
                printf("%-20s/%-2d %-15s %-15s %-10s\n", 
                       subnet_ip, new_cidr, "N/A", "N/A", "0");
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
    
    print_color(COLOR_BOLD, "Enter destination networks ");
    print_color(COLOR_CYAN, "(separate with spaces or commas):\n");
    printf("Destinations: ");
    
    if (!safe_input(input_line, sizeof(input_line))) {
        print_error("Input error");
        return;
    }
    
    char *token = strtok(input_line, ",");
    while (token != NULL && dest_count < MAX_DESTINATIONS) {
        while (*token == ' ' || *token == '\t') token++;
        
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }
        
        if (strlen(token) > 0 && strlen(token) < MAX_INPUT) {
            strncpy(destinations[dest_count], token, MAX_INPUT - 1);
            destinations[dest_count][MAX_INPUT - 1] = '\0';
            dest_count++;
        }
        
        token = strtok(NULL, ",");
    }
    
    if (dest_count == 0) {
        print_error("No valid destination networks provided");
        return;
    }
    
    print_color(COLOR_BOLD, "Enter next-hop IP address: ");
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
        if (validate_network_format(destinations[i])) {
            uint32_t dest_ip;
            int prefix_len;
            parse_ip_network(destinations[i], &dest_ip, &prefix_len);
            
            char formatted_dest[MAX_INPUT];
            char dest_ip_str[INET_ADDRSTRLEN];
            format_ip(dest_ip & cidr_to_mask(prefix_len), dest_ip_str);
            snprintf(formatted_dest, sizeof(formatted_dest), "%s/%d", dest_ip_str, prefix_len);
            
            printf("%-25s %-15s ", formatted_dest, next_hop);
            print_color(COLOR_GREEN, "Valid");
            printf("\n");
            valid_routes++;
        } else {
            printf("%-25s %-15s ", destinations[i], next_hop);
            print_color(COLOR_RED, "Invalid");
            printf("\n");
        }
    }
    
    printf("\n");
    print_color(COLOR_BOLD, "Summary: ");
    print_color(COLOR_GREEN, "%d", valid_routes);
    printf(" valid routes generated out of ");
    print_color(COLOR_CYAN, "%d", dest_count);
    printf(" destinations\n");
    
    if (valid_routes > 0) {
        printf("\n");
        print_color(COLOR_BOLD, "Export formats:\n");
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
                if (validate_network_format(destinations[i])) {
                    uint32_t dest_ip;
                    int prefix_len;
                    parse_ip_network(destinations[i], &dest_ip, &prefix_len);
                    
                    char formatted_dest[MAX_INPUT];
                    char dest_ip_str[INET_ADDRSTRLEN];
                    format_ip(dest_ip & cidr_to_mask(prefix_len), dest_ip_str);
                    snprintf(formatted_dest, sizeof(formatted_dest), "%s/%d", dest_ip_str, prefix_len);
                    
                    switch (choice) {
                        case 1:
                            print_color(COLOR_YELLOW, "ip route %s %s", formatted_dest, next_hop);
                            printf("\n");
                            break;
                        case 2:
                            print_color(COLOR_YELLOW, "route add -net %s gw %s", formatted_dest, next_hop);
                            printf("\n");
                            break;
                        case 3:
                        default:
                            print_color(COLOR_YELLOW, "%s => %s", formatted_dest, next_hop);
                            printf("\n");
                            break;
                    }
                }
            }
        }
    }
}

void manual_mode(void) {
    char input[MAX_INPUT];
    int choice;
    
    while (1) {
        print_separator();
        print_header("Manual Mode Menu");
        printf("1. Bitwise AND (IP and Mask)\n");
        printf("2. Decimal to Binary (Octet)\n");
        printf("3. Binary to Decimal\n");
        printf("4. CIDR to Binary Mask\n");
        printf("5. Subnetting\n");
        printf("6. Generate Routing Table (Multiple Destinations)\n");
        printf("7. Exit\n");
        
        print_color(COLOR_BOLD, "Select option (1-7): ");
        
        if (!safe_input(input, sizeof(input))) {
            print_error("Input error");
            continue;
        }
        
        choice = atoi(input);
        
        switch (choice) {
            case 1: {
                char ip[MAX_INPUT], mask[MAX_INPUT];
                print_color(COLOR_CYAN, "Enter IP address: ");
                if (!safe_input(ip, sizeof(ip))) continue;
                print_color(COLOR_CYAN, "Enter subnet mask or CIDR (e.g., 255.255.255.0 or /24): ");
                if (!safe_input(mask, sizeof(mask))) continue;
                bitwise_and_operation(ip, mask);
                break;
            }
            
            case 2: {
                print_color(COLOR_CYAN, "Enter decimal octet (0-255): ");
                if (!safe_input(input, sizeof(input))) continue;
                int octet = atoi(input);
                decimal_to_binary(octet);
                break;
            }
            
            case 3: {
                print_color(COLOR_CYAN, "Enter 8-bit binary (e.g., 11000000 or 1100 0000): ");
                if (!safe_input(input, sizeof(input))) continue;
                binary_to_decimal(input);
                break;
            }
            
            case 4: {
                print_color(COLOR_CYAN, "Enter CIDR (e.g., /24 or 24): ");
                if (!safe_input(input, sizeof(input))) continue;
                cidr_to_binary_mask(input);
                break;
            }
            
            case 5: {
                char network[MAX_INPUT], new_cidr_str[MAX_INPUT];
                print_color(COLOR_CYAN, "Enter network (e.g., 192.168.1.0/24 or 192.168.1.0 255.255.255.0): ");
                if (!safe_input(network, sizeof(network))) continue;
                print_color(COLOR_CYAN, "Enter new CIDR (e.g., /26 or 26): ");
                if (!safe_input(new_cidr_str, sizeof(new_cidr_str))) continue;
                subnetting(network, new_cidr_str);
                break;
            }
            
            case 6: {
                generate_routing_table();
                break;
            }
            
            case 7:
                print_success("Exiting manual mode");
                return;
                
            default:
                print_error("Invalid choice");
                break;
        }
        
        printf("\n");
        print_color(COLOR_BOLD, "Press Enter to continue...");
        getchar();
    }
}

void print_usage(const char *prog_name) {
    print_header("Network Configuration Tool");
    printf("Usage: %s [OPTIONS] [NETWORK]\n\n", prog_name);
    
    print_color(COLOR_BOLD, "OPTIONS:\n");
    printf("  -l, --lazy [NETWORK]     Lazy mode - analyze network (default)\n");
    printf("  -m, --manual             Manual mode - interactive menu\n");
    printf("  -h, --help               Show this help message\n");
    printf("  --no-color               Disable color output\n\n");
    
    print_color(COLOR_BOLD, "NETWORK FORMATS:\n");
    printf("  • IP/CIDR:     192.168.1.10/24\n");
    printf("  • IP MASK:     192.168.1.10 255.255.255.0\n");
    printf("  • IP CIDR:     192.168.1.10 24\n");
    printf("  • Just IP:     192.168.1.10 (assumes /32)\n\n");
    
    print_color(COLOR_BOLD, "EXAMPLES:\n");
    printf("  %s 192.168.1.10/24                    # Analyze network\n", prog_name);
    printf("  %s -l 10.0.0.0/8                     # Lazy mode\n", prog_name);
    printf("  %s -m                                 # Manual mode\n", prog_name);
    printf("  %s --no-color 172.16.0.0/12          # No colors\n", prog_name);

	print_color(COLOR_BOLD, "\nCoded by Yo-omega (https://github.com/Yo-omega)\n");
}

void init_colors(void) {
    if (!isatty(STDOUT_FILENO)) {
        use_colors = 0;
    }
}

int parse_args(int argc, char *argv[], char **network_input) {
    int mode = 1; 
    *network_input = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--lazy") == 0) {
            mode = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                *network_input = argv[++i];
            }
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--manual") == 0) {
            mode = 2;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            use_colors = 0;
        } else if (argv[i][0] != '-') {
        
            *network_input = argv[i];
        } else {
            print_error("Unknown option");
            printf("Use -h or --help for usage information\n");
            exit(1);
        }
    }
    
    return mode;
}

int main(int argc, char *argv[]) {
    char *network_input = NULL;
    char input[MAX_INPUT];
    int mode;
    
    init_colors();
    
    mode = parse_args(argc, argv, &network_input);

    print_separator();
    print_header("Network Configuration Tool v2.0");
    print_separator();
    
    if (mode == 1) {
        if (network_input) {
            lazy_mode(network_input);
        } else {
            print_color(COLOR_BOLD, "Enter network specification: ");
            if (!safe_input(input, sizeof(input))) {
                print_error("Input error");
                return 1;
            }
            lazy_mode(input);
        }
    } else if (mode == 2) {
        manual_mode();
    } else {
        print_error("Invalid mode");
        return 1;
    }
    
    printf("\n");
    print_success("Operation completed successfully");
    return 0;
}
