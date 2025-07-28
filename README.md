# Net Calculator

Net Calculator is a command-line tool for advanced network calculations and subnet analysis. It helps network engineers, students, and IT professionals quickly determine network/broadcast addresses, usable IP ranges, perform subnetting, and generate routing table entries.

## Features

- Analyze IP networks from a variety of input formats (CIDR, subnet mask, just IP)
- Display network, broadcast, subnet mask, host range, and number of hosts
- Perform bitwise operations between IP and masks
- Convert between decimal, binary, and hexadecimal for octets and masks
- Perform subnetting and display all subnets in a given range
- Generate routing table entries in multiple formats
- Supports colored terminal output

## How to Compile

This tool is written in C and requires a POSIX-compatible system (Linux, macOS, etc.) with a C compiler.

1. Ensure you have a C compiler installed (`gcc` or `clang`).
2. Download or clone the repository.
3. Build the program by running:

   ```sh
   gcc -o net_calculator net.c
   ```

   Or, if you want to include warnings and debugging:

   ```sh
   gcc -Wall -Wextra -g -o net_calculator net.c
   ```

## How to Use

Run the program from the command line:

```sh
./net_calculator [OPTIONS] [NETWORK]
```

### Options

- `-l`, `--lazy [NETWORK]` : Lazy mode (default). Analyzes the provided network.
- `-m`, `--manual`         : Manual mode. Interactive selection of network tools.
- `-h`, `--help`           : Show help message.
- `--no-color`             : Disable colored output.

### Network Input Formats

You may specify the target network in several formats:

- `IP/CIDR`      : `192.168.1.10/24`
- `IP MASK`      : `192.168.1.10 255.255.255.0`
- `IP CIDR`      : `192.168.1.10 24`
- `Just IP`      : `192.168.1.10` (assumes /32)

### Examples

- Analyze a network (lazy mode):

  ```sh
  ./net_calculator 192.168.1.10/24
  ```

- Start in lazy mode with a specified network:

  ```sh
  ./net_calculator -l 10.0.0.0/8
  ```

- Use manual mode for interactive menu:

  ```sh
  ./net_calculator -m
  ```

- Disable color output:

  ```sh
  ./net_calculator --no-color 172.16.0.0/12
  ```

### Manual Mode Features

Manual mode provides an interactive menu to:

- Perform bitwise AND (IP & mask)
- Convert decimal octet to binary/hex
- Convert binary octet to decimal/hex
- Convert CIDR to binary/decimal/hex mask
- Subnet a network and list all subnets
- Generate routing table entries for multiple destinations

---

Feel free to open issues or contribute improvements!