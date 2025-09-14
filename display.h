#ifndef DISPLAY_H
#define DISPLAY_H

#include "net.h"

void display_network_analysis(const network_info_t* info);
void print_usage(const char *prog_name);
void display_network_analysis_json(const network_info_t *info);

#endif
