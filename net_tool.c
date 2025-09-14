#include "net.h"
#include "network_calcs.h"
#include "utils.h"
#include "display.h"



int main(int argc, char *argv[]) {
    init_colors();

    int c;
    char *subnet_arg = NULL;
    int option_index = 0;
    int json_output = 0;

    static struct option long_options[] = {
        {"analyze",    required_argument, 0, 'a'},
        {"and",        required_argument, 0, 'n'},
        {"dec2bin",    required_argument, 0, 'd'},
        {"bin2dec",    required_argument, 0, 'b'},
        {"cidr2mask",  required_argument, 0, 'c'},
        {"subnet",     required_argument, 0, 's'},
        {"route-gen",  no_argument,       0, 'r'},
        {"vlsm",       required_argument, 0, 'v'},
        {"find-subnet", required_argument, 0, 'f'},
        {"no-color",   no_argument,       0, 'x'},
        {"json",       no_argument,       0, 'j'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    if (argc == 1) {
        print_usage(argv[0]);
        return 0;
    }

    while ((c = getopt_long(argc, argv, "a:n:d:b:c:s:rv:f:xhj", long_options, &option_index)) != -1) {
        switch (c) {
            case 'j':
                json_output = 1;
                break;
            case 'f':
                find_best_subnet(atoi(optarg));
                break;
            case 'a':
                lazy_mode(optarg);
                break;
            case 's':
                subnet_arg = optarg;
                if (optind < argc && argv[optind][0] != '-') {
                    subnetting(subnet_arg, argv[optind]);
                } else {
                    print_error("Subnetting requires a new CIDR value.");
                }
                break;
            case 'n':
                if (optind < argc && argv[optind][0] != '-') {
                    bitwise_and_operation(optarg, argv[optind]);
                } else {
                    print_error("Bitwise AND requires a mask or CIDR.");
                }
                break;
            case 'd':
                decimal_to_binary(atoi(optarg));
                break;
            case 'b':
                binary_to_decimal(optarg);
                break;
            case 'c':
                cidr_to_binary_mask(optarg);
                break;
            case 'r':
                generate_routing_table();
                break;
            case 'h':
                print_usage(argv[0]);
                break;
            case 0: // For --no-color
                if (strcmp("no-color", long_options[option_index].name) == 0) {
                    use_colors = 0;
                }
                break;
            case 'v':
                {
                    char *base_network = strtok(optarg, ",");
                    char *hosts_str = strtok(NULL, "");
                    if (!base_network || !hosts_str) {
                        print_error("VLSM requires base network and host counts (e.g., '192.168.1.0/24,10,20,30').");
                        return 1;
                    }

                    int host_reqs[MAX_SUBNETS];
                    int num_reqs = 0;
                    char *token = strtok(hosts_str, ",");
                    while(token != NULL && num_reqs < MAX_SUBNETS) {
                        host_reqs[num_reqs++] = atoi(token);
                        token = strtok(NULL, ",");
                    }
                    vlsm_calculator(base_network, host_reqs, num_reqs);
                }
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind < argc) {
        char full_input[MAX_INPUT] = {0};
        for (int i = optind; i < argc; i++) {
            strcat(full_input, argv[i]);
            if (i < argc - 1) {
                strcat(full_input, " ");
            }
        }
        if (strlen(full_input) > 0) {
             if (json_output) {
                // Placeholder for JSON output call
                uint32_t ip;
                int prefix_len;
                network_info_t info;
                if (parse_ip_network(full_input, &ip, &prefix_len) && calculate_network_info(ip, prefix_len, &info)) {
                    display_network_analysis_json(&info);
                } else {
                    print_error("Invalid input for analysis.");
                }
            } else {
                lazy_mode(full_input);
            }
        }
    }

    return 0;
}
