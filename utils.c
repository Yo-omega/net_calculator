#include "net.h"
#include "utils.h"

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

int safe_input(char *buffer, int size) {
    if (!fgets(buffer, size, stdin)) {
        // Handle EOF or read error
        buffer[0] = '\0';
        return 0;
    }
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len-1] == '\n') {
        buffer[len-1] = '\0';
    } else {
        // Clear the rest of the input buffer if input was too long
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
    }
    return 1;
}

void init_colors(void) {
    if (!isatty(STDOUT_FILENO) || getenv("NO_COLOR")) {
        use_colors = 0;
    }
}
