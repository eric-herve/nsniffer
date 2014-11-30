# nsniffer.py

## About

This python script is a tcpdump wrapper.

It essentially allows :
- to assemble requests and responses
- to calculate the response time of requests (duration between twice first packets of request and response)
- to match with regex multiple fields (duration, content, ...)
- to colorize output and matching
- to display statistics layer 7

It is only compatible with IPv4 and TCP/UDP.

## Configuration

### Requirement

- BSD/Linux system (tested on OS X Yosemite, Debian lenny/squeeze/wheezy)
- tcpdump +4.0
- python +2.6 (python 3 untested)

### Services

This script uses '/etc/services' to identify services. 
For services that are not in this database, you can add them into the dictionnary 'services_custom' of the script.

```
services_custom = {
    'TCP81': 'http',
    'UDP892': 'nfs_mountd',
    'TCP3307': 'mysql',
    'TCP6081': 'http_varnish',
    'TCP6379': 'redis',
    'TCP8080': 'http',
    'TCP8081': 'http',
    'TCP31000': 'activemq_jvm',
    'TCP32000': 'activemq_wrapper',
    'TCP61613': 'activemq',
    'TCP61616': 'activemq'
}
```

Just simply add a key and a value as follows :

`'<protocol><port_number>', '<name>'`

Example: 

`'TCP3307', 'mysql'`

## Arguments

| Argument | Description |
| -------- | ----------- |
|`-d DEVICE, --device=DEVICE`|By default tcpdump will select a default interface to listen on. Use this option to force tcpdump to listen on interface DEVICE ('any' for any devices)|
|`-F, --tcpdump-filter=FILTER`|Filter layer 3/4. Use tcpdump filter (for details, see tcpdump manual)|
|`-E, --extra-filter=REGEX`|Filter layer 7. Match with regex in the extra fields ('-f' and/or '-c' needed)|
|`-i, --ignore-case-match`|Ignore case distinctions in matching|
|`-v NAME, --view=NAME`|Display view ('normal', 'pretty' or 'batch', default: normal)|
|`-X, --extra`|Display extra statistics for any and matched requests|
|`--extra-any`|Display extra statistics for any requests|
|`--extra-matched`|Display extra statistics for matched requests|
|`-l, --by-line`|Display content line by line|
|`-f, --filter-match`|Display only the requests that are matched|
|`-c, --color`|Active colorization (in particular with matching)|
|`-t, --translate-ip`|If possible, host lookup (warning: if lookup is too slow, it will be automaticaly disabled)|
|`-S SIZE, --content-size=SIZE`|Limit the string size (display only) of content|
|`--request-content-size=SIZE`|Limit the string size (display only) of request content|
|`--response-content-size=SIZE`|Limit the string size (display only) of response content|
|`--no-response-content`|Don't display the request content (disabled in batch view)|
|`--apple-version`|Some versions of tcpdump on Apple systems need this argument|
|`--extra-http-uri-level1`|Display extra statistics by uri (level1) ('--extra'* needed)|
|`-I, --input-pcap=FILE`|Input file pcap_dump into tcpdump ('-' from stdin)|
|`--verbose`|Display verbose informations (critical, error, warning, info)|
|`--debug`|Display debug informations ('--verbose' + debug)|
|`-h, --help`|Display this help and exit|

## Examples

```
# ./nsniffer.py -d any -tl -S 256 -f -E 'request_content "test"'
/*----------------------------------------*/

xxx.xxx.xxx.xxx:46738 > 173.194.71.94:80 (xxxxxxxxxxxxxxx > lb-in-f94.1e100.net)
service  : www (TCP)
duration : 0.04396s
request content (2014/10/11 17:24:32.576231)

GET /test HTTP/1.0%
Host: www.google.fr%
Accept: text/html, text/plain, text/css, text/sgml, */*;q=0.01%
Accept-Encoding: gzip, compress, bzip2%
Accept-Language: en%
User-Agent: Lynx/2.8.8dev.5 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.8.6%
%

response content (2014/10/11 17:24:32.620190)

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
./nsniffer.py -d eth0 -S 256 -f -E 'request_content "test"' -v 'batch'
;;;;dst;;;;src;;;;service;;;;start_time;;;;end_time;;;;duration;;;;request_content;;;;response_content
;;;;xxx.xxx.xxx.xxx:46739;;;;173.194.71.94:80;;;;www;;;;2014/10/11 17:37:10.748520;;;;2014/10/11 17:37:10.794552;;;;0.04603;;;;GET /test HTTP/1.0%Host: www.google.fr%Accept: text/html, text/plain, text/css, text/sgml, */*;q=0.01%Accept-Encoding: gzip, compress, bzip2%Accept-Language: en%User-Agent: Lynx/2.8.8dev.5 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.8.6%%;;;;HTTP/1.0 404 Not Found%Content-Type: text/html; charset=UTF-8%X-Content-Type-Options: nosniff%Date: Sat, 11 Oct 2014 15:37:07 GMT%Server: sffe%Content-Length: 1429%X-XSS-Protection: 1; mode=block%Alternate-Protocol: 80:quic,p=0.01%%<!DOCTYPE html><html lan
```
