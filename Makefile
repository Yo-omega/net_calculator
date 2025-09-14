CC=gcc
CFLAGS=-Wall -Wextra -g
TARGET=net_tool
SRC=net_tool.c utils.c display.c network_calcs.c
OBJ=$(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET) test_runner

test:
	$(CC) $(CFLAGS) -o test_runner tests/test_network_calcs.c network_calcs.c utils.c display.c -I.
	./test_runner

.PHONY: all clean test
