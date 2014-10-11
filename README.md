# nsniffer.py

## About

This python script is a Linux ngrep wrapper.

It essentially allows :
- to assemble requests and responses
- to calculate the response time to requests
- to match with regex
- to match with duration threshold
- to colorize output and matching

It is only compatible with IPv4 and TCP/UDP.

## Configuration

### Requirement

- ngrep 1.x
- python 2.7

### Services

This script uses '/etc/services' to identify services. 
For services that are not in this database, you can add them into the dictionnary 'services_custom' of the script.

```
services_custom = {
    'T81': 'www',
    'T3307': 'mysql',
    'T8080': 'www',
    'T8081': 'www',
    'T61613': 'activemq',
    'T61616': 'activemq'
}
```

Just simply add a key and a value as follows (protocol = 'T' for 'tcp' or 'U' for 'udp') :

`'<protocol><port_number>', '<name>'`

Example: 

`'T3307', 'mysql'`

### Non-printable character

ngrep use by default '*' for non-printable character.
nsniffer user by default '%'.

If necessary, this character can be replaced via the variable 'non_printable_char'.

## Arguments

`-d DEVICE, --device DEVICE` By default ngrep will select a default interface to listen on. Use this option to force ngrep to listen on interface DEVICE ('any' for all).

`-F, --ngrep-filter` ngrep filter (for details, see ngrep manual.

`-v NAME, --view=NAME` Display view ('normal', 'pretty' or 'batch', default: normal).

`-D SEC, --duration-threshold=SEC` Match the requests higher than the threshold (in seconds with dot) (only used with '-f' and/or '-c').

`-m, --regex-match=REGEX` Match with regex in the request or/and the response content (only used with '-f' and/or '-c').

`--request-regex-match=REGEX` Match with regex in the request content (only used with '-f' and/or '-c').

`--response-regex-match=REGEX` Match with regex in the response content (only used with '-f' and/or '-c').

`-i, --ignore-case-match` Ignorcase distinctions in matching.

`-f, --filter-match` Display only the requests that are matched.

`-c, --color` Active colorization.

`-l, --by-line` Display content line by line.

`-t, --translate-ip` If possible, host lookup (warning: if lookup is too slow, it will be automaticaly disabled).

`-S SIZE, --content-size=SIZE` Limit the string size (display only) of content.

`--request-content-size=SIZE` Limit the string size (display only) of request content.

`--response-content-size=SIZE` Limit the string size (display only) of response content.

`--no-response-content` Don't display the request content (disabled in batch view).

`-I, --input-pcap=FILE` Input file  pcap_dump into ngrep.

`-O, --output-pcap=FILE` Output packets to a pcap-compatible dump file.

`-h, --help` Display help.

## Examples

```
# ./nsniffer.py -d any -tl -S 256 -f -m 'test'
/*----------------------------------------*/

195.154.118.114:46738 > 173.194.71.94:80 (sd-21861.dedibox.fr > lb-in-f94.1e100.net)
service  : www (T)
duration : 0.04396s
request (2014/10/11 17:24:32.576231)

GET /test HTTP/1.0%
Host: www.google.fr%
Accept: text/html, text/plain, text/css, text/sgml, */*;q=0.01%
Accept-Encoding: gzip, compress, bzip2%
Accept-Language: en%
User-Agent: Lynx/2.8.8dev.5 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.8.6%
%

response (2014/10/11 17:24:32.620190)

HTTP/1.0 404 Not Found%
Content-Type: text/html; charset=UTF-8%
X-Content-Type-Options: nosniff%
Date: Sat, 11 Oct 2014 15:24:29 GMT%
Server: sffe%
Content-Length: 1429%
X-XSS-Protection: 1; mode=block%
Alternate-Protocol: 80:quic,p=0.01%
%
<!DOCTYPE html
```

```
./nsniffer.py -d eth0 -S 256 -f -m 'test' -v 'batch'
;;;;dst;;;;src;;;;service;;;;start_time;;;;end_time;;;;duration;;;;request_content;;;;response_content
;;;;195.154.118.114:46739;;;;173.194.71.94:80;;;;www;;;;2014/10/11 17:37:10.748520;;;;2014/10/11 17:37:10.794552;;;;0.04603;;;;GET /test HTTP/1.0%Host: www.google.fr%Accept: text/html, text/plain, text/css, text/sgml, */*;q=0.01%Accept-Encoding: gzip, compress, bzip2%Accept-Language: en%User-Agent: Lynx/2.8.8dev.5 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.8.6%%;;;;HTTP/1.0 404 Not Found%Content-Type: text/html; charset=UTF-8%X-Content-Type-Options: nosniff%Date: Sat, 11 Oct 2014 15:37:07 GMT%Server: sffe%Content-Length: 1429%X-XSS-Protection: 1; mode=block%Alternate-Protocol: 80:quic,p=0.01%%<!DOCTYPE html><html lan
```
