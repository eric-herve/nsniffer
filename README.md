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

`# timeout 3600 ./nsniffer.py -d eth0 -f -D 2 -O /var/log/ngrep.pcap`

`# ./nsniffer.py -d eth0 -c -D 3 -I /var/log/ngrep.pcap`

`#./nsniffer.py -d any -t --no-response-content`

`# ./nsniffer.py -d any -F 'host 1.2.3.4' -v pretty -m 'GET|POST' -lc`

`# ./nsniffer.py -d any -F 'port 80' -tc -m 'GET \S*|HTTP/1.1 [12345][\d]{2}' -S 256 -D 0.2 -v batch`

`# ./nsniffer.py -d any -F 'port 80' -tcf -m 'GET|HTTP/1.1 [45][\d]{2}' --response-content-size=50`
