# TraceInfo

A simple script providing basic information about a packet capture. The result is required for dataset normalization and annotation.


## Usage

Script functions will be part of the web application but you can easily use them separately.

### Basic commands

- `$ ./trace-info.py -f <capture_file> -t -p -c` – provides all basic information about given capture
    - `-t` – show statistics about TCP conversations
    - `-p` – show mapping of MAC addresses to IP addresses
    - `-c` – show properties of the capture file

### Requirements

- `tshark` and `capinfos` tools
- `termcolor` python module


