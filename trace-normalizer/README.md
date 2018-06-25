# TraceNormalizer

A script facilitating normalization of packet trace capture to change IP and MAC addresses, and reset capture timestamps to epoch time.

## Usage

Script functions will be part of the web application, but you can easily use them separately.


### Basic commands

- `$ ./trace-normalizer.py -i <input_file> -o <output_file> -c <configuration>` – perform normalization based on given JSON configuration
    - please note that input file is converted to PCAP format at the beginning and to PCAP-Ng format at the end (due to limitations of used tools).

- Below you can see an example of a configuration file (each of elements "IP", "MAC", "timestamp" is optional):
```
{
  "IP": [
    {
      "original": "203.0.113.2",
      "new": "240.0.0.2"
    },
    {
      "original": "203.0.113.101",
      "new": "240.128.0.2"
    }
  ],
  "MAC": [
    {
      "original": "08:00:27:49:be:1a",
      "new": "00:00:00:00:00:01"
    },
    {
      "original": "08:00:27:fb:83:c7",
      "new": "00:00:00:00:01:01"
    }
  ],
  "timestamp": "1528440804.539984454"
}
```

### Requirements

- `tcprewrite`, `editcap`, and `bittwiste` tools
- `termcolor` python module
