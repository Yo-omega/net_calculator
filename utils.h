#ifndef UTILS_H
#define UTILS_H

#include "net.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

extern int use_colors;

#define MAX_INPUT 256
#define MAX_SUBNETS 1024

void print_color(const char* color, const char* format, ...);
void print_error(const char* msg);
void print_success(const char* msg);
void print_warning(const char* msg);
void print_info(const char* msg);
void print_header(const char* text);
void print_separator(void);
int safe_input(char *buffer, int size);
void init_colors(void);

#endif
