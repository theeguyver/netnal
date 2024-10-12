
# netnAL
```
               __             _____  .____     
  ____   _____/  |_  ____    /  _  \ |    |    
 /    \_/ __ \   __\/    \  /  /_\  \|    |    
|   |  \  ___/|  | |   |  \/    |    \    |___ 
|___|  /\___  >__| |___|  /\____|__  /_______ \
     \/     \/          \/         \/        \/
```
A simple CLI Network Scanner written in Python.

## Overview
**Netnal** is a command-line network analysis tool that helps you perform various types of network scans and checks. It supports SYN, UDP, ACK, NULL, and XMAS scans, along with ping checks and traceroutes.

## Usage
Being a Python Based Network Scanner, you need to have Python installed in order to run it. Once you have Python3 installed, you can run the tool by typing the following command into the terminal/CLI with appropriate parameters.
```
python -m netnal -sS/-sU/-sA/-sN/-sX/-p/-t address [port1-port2-port3]/[start:end]
```

## Flags
Currently, netnal supports the following flags. 
  - ```-sS```    :  **SYN**  :   Perform SYN scan
  - ```-sU```    :  **UDP**  :   Perform UDP scan
  - ```-sA```    :  **ACK**  :   Perform ACK scan
  - ```-sN```    :  **NULL** :   Perform NULL scan
  - ```-sX```   :  **XMAS** :   Perform XMAS scan
  - ```-p```   :  **ping** :   Perform ping check
  - ```-t```    : **trace** :   Perform traceroute
## Port
You can specify port numbers individually or as a range:

- `--default`          : Scans ports 1 - 1023 of the specified address  
- `port1`              : Scans a single port (port1) of the specified address  
- `port1-port2-port3`  : Scans multiple ports (port1, port2, port3) of the specified address  
- `port1:port_n`       : Scans a range of ports from port1 to port_n of the specified address  

## Example Commands

- **SYN scan on ports 80 and 443**:
  ```bash
  python -m netnal -sS 192.168.1.1 80-443
  ```

- **UDP scan on all ports from 1000 to 2000**:
  ```bash
  python -m netnal -sU 192.168.1.1 1000:2000
  ```

- **Perform ping check**:
  ```bash
  python -m netnal -p 192.168.1.1
  ```

## License

This project is licensed under the MIT License.
