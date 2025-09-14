#include <stdio.h>
#include <assert.h>
#include "../network_calcs.h"

void test_cidr_to_mask(void) {
    printf("Running tests for cidr_to_mask... ");
    assert(cidr_to_mask(32) == 0xFFFFFFFF);
    assert(cidr_to_mask(24) == 0xFFFFFF00);
    assert(cidr_to_mask(16) == 0xFFFF0000);
    assert(cidr_to_mask(8) == 0xFF000000);
    assert(cidr_to_mask(0) == 0x00000000);
    assert(cidr_to_mask(1) == 0x80000000);
    assert(cidr_to_mask(31) == 0xFFFFFFFE);
    printf("Passed!\n");
}

void test_mask_to_cidr(void) {
    printf("Running tests for mask_to_cidr... ");
    assert(mask_to_cidr(0xFFFFFFFF) == 32);
    assert(mask_to_cidr(0xFFFFFF00) == 24);
    assert(mask_to_cidr(0xFFFF0000) == 16);
    assert(mask_to_cidr(0xFF000000) == 8);
    assert(mask_to_cidr(0x00000000) == 0);
    assert(mask_to_cidr(0x80000000) == 1);
    assert(mask_to_cidr(0xFFFFFFFE) == 31);
    assert(mask_to_cidr(0xFFFFF0FF) == -1); // Non-contiguous
    printf("Passed!\n");
}

void test_calculate_network_info(void) {
    printf("Running tests for calculate_network_info... ");
    network_info_t info;
    uint32_t ip;
    parse_ip("192.168.1.100", &ip);

    calculate_network_info(ip, 24, &info);
    assert(info.network_address == 0xC0A80100);
    assert(info.broadcast_address == 0xC0A801FF);
    assert(info.first_host_address == 0xC0A80101);
    assert(info.last_host_address == 0xC0A801FE);
    assert(info.host_count == 254);
    assert(info.prefix_length == 24);

    calculate_network_info(ip, 31, &info);
    assert(info.network_address == 0xC0A80164);
    assert(info.broadcast_address == 0xC0A80165);
    assert(info.host_count == 2);

    calculate_network_info(ip, 32, &info);
    assert(info.network_address == 0xC0A80164);
    assert(info.broadcast_address == 0xC0A80164);
    assert(info.host_count == 0);

    printf("Passed!\n");
}

int main(void) {
    test_cidr_to_mask();
    test_mask_to_cidr();
    test_calculate_network_info();
    printf("\nAll tests passed successfully!\n");
    return 0;
}
