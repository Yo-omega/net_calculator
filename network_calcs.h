#ifndef NETWORK_CALCS_H
#define NETWORK_CALCS_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int prefix_length;
    uint32_t subnet_mask;
    uint32_t network_address;
    uint32_t broadcast_address;
    uint32_t first_host_address;
    uint32_t last_host_address;
    uint32_t host_count;
} network_info_t;

int parse_ip(const char *ip_str, uint32_t *ip_int);
void format_ip(uint32_t ip_int, char *ip_str, size_t ip_str_len);
uint32_t cidr_to_mask(int prefix_length);
int mask_to_cidr(uint32_t mask);
int parse_cidr(const char *input);
int parse_ip_network(const char *input, uint32_t *ip, int *prefix_len);
int calculate_network_info(uint32_t ip, int prefix_len, network_info_t *info);
void lazy_mode(const char *input);
void bitwise_and_operation(const char *ip_str, const char *mask_input);
void decimal_to_binary(int octet);
void binary_to_decimal(const char *binary_input);
void cidr_to_binary_mask(const char *cidr_input);
void subnetting(const char *network_str, const char *new_cidr_str);
int validate_network_format(const char *network);
void generate_routing_table(void);
void format_binary(uint32_t num, char* out_str, size_t out_len);
void vlsm_calculator(const char *base_network_str, const int *host_requirements, int num_subnets);
void find_best_subnet(int required_hosts);

#endif
