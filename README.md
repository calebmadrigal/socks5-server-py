# socks5-server-py

A basic [SOCKS5](https://en.wikipedia.org/wiki/SOCKS#SOCKS5) proxy server in a single Python script (with no 3rd party dependencies).

Should work with Python 2.6+

## Usage

Tab 1: `python socks5_server.py`
* Start the SOCKS5 server on the default port 1080

Tab 2: `echo hello | nc -vv -l 6000`
* Use [netcat](https://en.wikipedia.org/wiki/Netcat) to start a simple server

Tab 3: `nc -X 5 -x localhost:1080 localhost 6000`
* Use netcat to connect to the netcat server via the proxy.

```
cmadrigal-MBP:socks5_server caleb.madrigal$ python socks5_server.py -h
usage: socks5_server.py [-h] [-s HOST] [-p PORT] [--log-path LOG_PATH]
                        [--log-level LOG_LEVEL]

optional arguments:
  -h, --help            show this help message and exit
  -s HOST, --host HOST  IP/Hostname to serve on
  -p PORT, --port PORT  Port to serve on
  --log-path LOG_PATH   DEBUG, INFO, WARNING, ERROR, or CRITICAL
  --log-level LOG_LEVEL
                        Log file path
```

