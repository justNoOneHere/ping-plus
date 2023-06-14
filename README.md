# Ping+ 
The Ping+ script is a command-line utility that provides additional functionalities compared to the standard 'ping' command. It has been developed from scratch to offer features such as whois, nslookup, and port scanning. This README will guide you on how to install, configure, and use the Ping+ script effectively.

Here are some examples of how you can use the script :

- Perform a basic ping:

```
python ping.py example.com
```

This will send 4 ICMP echo requests to "example.com" with a payload size of 32 bytes.

- Specify the number of packets and timeout:

```
python ping.py example.com -c 10 -t 2
```

This will send 10 ICMP echo requests to "example.com" with a timeout of 2 seconds for each request.

- Set the payload size:

```
python ping.py example.com -s 64
```

This will send ICMP echo requests to "example.com" with a payload size of 64 bytes.

- Perform a WHOIS lookup:

```
python ping.py example.com -w
```

This will send ICMP echo requests to "example.com" and perform a WHOIS lookup for the host.

- Perform an NSLookup:

```
python ping.py example.com -n
```

This will send ICMP echo requests to "example.com" and perform an NSLookup to retrieve the IP addresses associated with the host.

- Perform a port scan:

```
python ping.py example.com --scan-port
```

This will send ICMP echo requests to "example.com" and perform a port scan from port 1 to 65535.

- Specify the range of ports for port scanning:

```
python ping.py example.com --scan-port --start-port 80 --end-port 100
```

This will send ICMP echo requests to "example.com" and perform a port scan from port 80 to 100.

- Set the Time To Live (TTL) value:

```
python ping.py example.com -T 64
```

This will send ICMP echo requests to "example.com" with a TTL value of 64.

- Adjust the interval between packets:

```
python ping.py example.com -i 0.5
```

This will send ICMP echo requests to "example.com" with an interval of 0.5 seconds between each packet.

- Enable both WHOIS lookup and NSLookup:

```
python ping.py example.com -w -n
```

And more ...
