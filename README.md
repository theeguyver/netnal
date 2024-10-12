               __             _____  .____     
  ____   _____/  |_  ____    /  _  \ |    |    
 /    \_/ __ \   __\/    \  /  /_\  \|    |    
|   |  \  ___/|  | |   |  \/    |    \    |___ 
|___|  /\___  >__| |___|  /\____|__  /_______ \
     \/     \/          \/         \/        \/


Usage: python -m netnal -sS/-sU/-sA/-sN/-sX/-p/-t address [port1-port2-port3]/[start:end]


Flags:
  -sS    :  SYN  :   Perform SYN scan
  -sU    :  UDP  :   Perform UDP scan
  -sA    :  ACK  :   Perform ACK scan
  -sN    :  NULL :   Perform NULL scan
  -sX    :  XMAS :   Perform XMAS scan
  -p :   :  ping :   Perform ping check
  -t :   : trace :   Perform traceroute

Port Number Specifications:

  You can specify ports individually or as a range.
  --default          :   will scan port 1 - 1023 of specified address.
  port1              :   will scan port1 of specified address.
  port1-port2-port3  :   will scan port1, port2, port3 of specified address.
  port1:port_n       :   will scan port1 to port_n of specified address