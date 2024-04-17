#ifndef TERMINAL_COLORS_H
#define TERMINAL_COLORS_H

#include <stdio.h>

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

#define print_error(fmt, ...) printf(RED fmt RESET "\n", ##__VA_ARGS__)
#define print_success(fmt, ...) printf(GRN fmt RESET "\n", ##__VA_ARGS__)
#define print_info(fmt, ...) printf(CYN fmt RESET "\n", ##__VA_ARGS__)
#define print_options(fmt, ...) printf(BLU fmt RESET "\n", ##__VA_ARGS__)

#endif // TERMINAL_COLORS_H