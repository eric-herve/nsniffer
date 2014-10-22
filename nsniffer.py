#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
nsniffer.py : Linux Ngrep wrapper.

Author  : Eric Herve <eric.herve.fr@gmail.com>
Version : 0.1

"""

import getopt
import os
import re
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime


def usage():
    """Usage of this script."""

    script_name = sys.argv[0]
    print """
ngrep wrapper (only ipv4 and tcp/udp).

optional arguments:
  -d DEVICE, --device DEVICE         By default ngrep will select a default interface to listen on.
                                     Use this option to force ngrep to listen on interface DEVICE
                                     ('any' for all).
  -F, --ngrep-filter                 ngrep filter (for details, see ngrep manual.
  -v NAME, --view=NAME               Display view ('normal', 'pretty' or 'batch', default: normal).
  -D SEC, --duration-threshold=SEC   Match the requests higher than the threshold
                                     (in seconds with dot) (only used with '-f' and/or '-c').
  -m, --regex-match=REGEX            Match with regex in the request or/and the
                                     response content (only used with '-f' and/or '-c').
  --request-regex-match=REGEX        Match with regex in the request content (only used with '-f' and/or '-c').
  --response-regex-match=REGEX       Match with regex in the response content (only used with '-f' and/or '-c').
  -i, --ignore-case-match            Ignore case distinctions in matching.
  -f, --filter-match                 Display only the requests that are matched.
  -c, --color                        Active colorization.
  -l, --by-line                      Display content line by line.
  -t, --translate-ip                 If possible, host lookup (warning: if lookup
                                     is too slow, it will be automaticaly disabled).
  -S SIZE, --content-size=SIZE       Limit the string size (display only) of content.
  --request-content-size=SIZE        Limit the string size (display only) of request content.
  --response-content-size=SIZE       Limit the string size (display only) of response content.
  --no-response-content              Don't display the request content (disabled in batch view).
  -I, --input-pcap=FILE              Input file  pcap_dump into ngrep.
  -O, --output-pcap=FILE             Output packets to a pcap-compatible dump file.
  -h, --help                         Display this help and exit.
"""

    print "examples :"
    print "  # timeout 3600 %s -d eth0 -f -D 2 -O /var/log/ngrep.pcap" % script_name
    print "  # %s -d eth0 -c -D 3 -I /var/log/ngrep.pcap" % script_name
    print "  # %s -d any -t --no-response-content" % script_name
    print "  # %s -d any -F 'host 1.2.3.4' -v pretty -m 'GET|POST' -lc" % script_name
    print "  # %s -d any -F 'port 80' -tc -m 'GET \\S*|HTTP/1.1 [12345][\\d]{2}' -S 256 -D 0.2 -v batch" % script_name
    print "  # %s -d any -F 'port 80' -tcf -m 'GET|HTTP/1.1 [45][\\d]{2}' --response-content-size=50" % script_name
    print
    sys.exit(2)


def display_stats():
    """Display statistics."""

    # Calculation of the capture duration
    end_time = datetime.now()
    capture_duration = str(end_time - start_time)

    # Display time informations
    print
    print "Period"
    print
    print "#" * 56
    print "First request               : %s" % start_time
    print "Last request                : %s" % end_time
    print "Total duration              : %18s hour(s)" % capture_duration
    print "#" * 56
    print
    print "Parameters"
    print
    print "#" * 56
    print "View                        : %s" % view
    if input_pcap_file:
        print "Input pcap file             : %s" % input_pcap_file
    if output_pcap_file:
        print "Output pcap file            : %s" % output_pcap_file
    if output_file:
        print "Output file                 : %s" % output_file
    if ngrep_interface:
        print "ngrep interface             : %s" % ngrep_interface
    if ngrep_filter:
        print "ngrep filter                : '%s'" % ngrep_filter
    if regex_match['request'] and regex_match['response']:
        print "Request/response match      : '(%s)'" % regex_match['request']
    elif regex_match['request']:
        print "Request match               : '(%s)'" % regex_match['request']
    elif regex_match['response']:
        print "Response match              : '(%s)'" % regex_match['response']
    if duration_threshold:
        print "Duration threshold (in s)   : %s" % duration_threshold
    if ignore_case_match:
        print "Ignore case match           : %s" % ignore_case_match
    if by_line:
        print "By line                     : %s" % by_line
    if color:
        print "Color                       : %s" % color
    if filter_match:
        print "Filter                      : %s" % filter_match
    if translate_ip:
        print "Translate IP                : %s" % translate_ip
    if 'request' in content_size:
        if content_size['response']:
            print "Request content size        : %s" % content_size['request']
    if no_display_response_content:
        print "No response content display : True"
    else:
        if 'response' in content_size:
            if content_size['response']:
                print "Response content size       : %s" % content_size['response']
    print "#" * 56

    if stat or stat_matched or extra:
        print
        print "#" * 10
        print "STATISTICS"
        print "#" * 10

    if stat:
        print
        print "-" * 12
        print "ALL requests"
        print "-" * 12
        print
        print "- Number of requests and response time :"
        for protocol in stat:
            for service in stat[protocol]:
                average = stat[protocol][service]['duration'] / stat[protocol][service]['counter']
                print "%12s (%s) : %6s request(s) in %0.5fs (average: %0.5fs, max: %0.5fs)" \
                    % (service, protocol, stat[protocol][service]['counter'],
                       stat[protocol][service]['duration'], average, stat[protocol][service]['max'])

    if extra:
        print
        print "- Extra stats by service :"
        for service in extra:
            if service == 'http':
                print "%7s %s by host :" % ('', service)
                for host in sorted(extra[service]['host']):
                    print "%15sHost '%s' :" % (' ', host)
                    for status_code in sorted(extra[service]['host'][host]):
                        average = extra[service]['host'][host][status_code]['duration'] / \
                            extra[service]['host'][host][status_code]['count']
                        print "%20s-> %-30s : %6s request(s) in %0.5fs (average: %0.5fs, max: %0.5fs)" \
                            % (' ', status_code, extra[service]['host'][host][status_code]['count'],
                               extra[service]['host'][host][status_code]['duration'], average,
                               extra[service]['host'][host][status_code]['max'])
                print "%7s %s by host and uri level1 :" % ('', service)
                for host in sorted(extra[service]['uri_level1']):
                    print "%15sHost '%s' :" % (' ', host)
                    for status_code in sorted(extra[service]['uri_level1'][host]):
                        average = extra[service]['uri_level1'][host][status_code]['duration'] / \
                            extra[service]['uri_level1'][host][status_code]['count']
                        print "%20s-> %-30s : %6s request(s) in %0.5fs (average: %0.5fs, max: %0.5fs)" \
                            % (' ', status_code, extra[service]['uri_level1'][host][status_code]['count'],
                               extra[service]['uri_level1'][host][status_code]['duration'], average,
                               extra[service]['uri_level1'][host][status_code]['max'])
            elif service == 'mysql':
                print "%7s %s :" % ('', service)
                if 'command' in extra[service]:
                    print "%15sCommands :" % ' '
                    for command in sorted(extra[service]['command']):
                        average = extra[service]['command'][command]['duration'] / \
                            extra[service]['command'][command]['count']
                        print "%20s-> %-30s : %6s request(s) in %0.5fs (average: %0.5fs, max: %0.5fs)" \
                            % (' ', command, extra[service]['command'][command]['count'],
                               extra[service]['command'][command]['duration'], average,
                               extra[service]['command'][command]['max'])
                if 'select' in extra[service]:
                    print "%15sCommand 'SELECT' details (database.table) :" % ' '
                    for select in sorted(extra[service]['select']):
                        average = extra[service]['select'][select]['duration'] / \
                            extra[service]['select'][select]['count']
                        if len(select) <= 30:
                            print "%20s-> %-30s : %6s request(s) in %0.5fs (average: %0.5fs, max: %0.5fs)" \
                                % (' ', select, extra[service]['select'][select]['count'],
                                   extra[service]['select'][select]['duration'], average,
                                   extra[service]['select'][select]['max'])
                        else:
                            print "%20s-> %-30s :\n%55s %6s request(s) in %0.5fs (average: %0.5fs, max: %0.5fs)" \
                                % (' ', select, ' ', extra[service]['select'][select]['count'],
                                   extra[service]['select'][select]['duration'], average,
                                   extra[service]['select'][select]['max'])

    if stat_matched and filter_match:
        print
        print "-" * 16
        print "MATCHED requests"
        print "-" * 16
        print
        print "- Number of requests and response time :"
        for protocol in stat_matched:
            for service in stat_matched[protocol]:
                average = stat_matched[protocol][service]['duration'] / stat_matched[protocol][service]['counter']
            print "%12s (%s) : %6s request(s) in %0.5fs (average: %0.5fs, max %0.5fs)" \
                % (service, protocol, stat_matched[protocol][service]['counter'],
                   stat_matched[protocol][service]['duration'], average, stat_matched[protocol][service]['max'])
    print


def signal_end(signum, frame):
    """Display stats and exit."""

    # Processing last text block if exists
    if text_block:
        process(text_block)

    # Display
    display_stats()
    sys.exit(0)


def process(text):
    """Consolidate packets data."""
    global translate_ip

    regex = r"^([TU]) ([\d]{4}\/[\d]{2}\/[\d]{2} [\d]{2}:[\d]{2}:[\d]{2}.[\d]{6}) ([\d.:]+:[\d]+) -> ([\d.:]+:[\d]+)(?: \[([\w]+)\])?(.*)"
    m = re.search(regex, text, flags=re.DOTALL)
    if m:
        duration_color = ""
        protocol = m.group(1)
        timeh = m.group(2)
        # Convert human time in timestamp
        try:
            td = datetime.strptime(timeh, '%Y/%m/%d %H:%M:%S.%f') - datetime(1970, 1, 1)
            timet = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 1e6
        except AttributeError:
            # Used in some CTRL + C
            return
        src = m.group(3)
        dst = m.group(4)
        tcp_flag = m.group(5)
        content = m.group(6)
        packet = "%s -> %s" % (src, dst)
        packet_reverse = "%s -> %s" % (dst, src)

        m = re.match('(.*):(.*) -> (.*):(.*)', packet)
        ip_src = m.group(1)
        port_src = int(m.group(2))
        ip_dst = m.group(3)
        port_dst = int(m.group(4))

        # Get service name
        service_src = None
        service_dst = None
        if '%s%s' % (protocol, port_src) in services_custom:
            service_src = services_custom['%s%s' % (protocol, port_src)]
        elif '%s%s' % (protocol, port_dst) in services_custom:
            service_dst = services_custom['%s%s' % (protocol, port_dst)]
        else:
            try:
                service_src = socket.getservbyport(port_src)
            except socket.error:
                service_src = None
            try:
                service_dst = socket.getservbyport(port_dst)
            except socket.error:
                service_dst = None

        if service_src:
            packet_type = "response"
            service = service_src
        elif service_dst:
            packet_type = "request"
            service = service_dst
        else:
            packet_type = "unknown"
            service = "unknown"

        if service == 'www':
            service = 'http'

        # Exclude 'R'eset requests
        if tcp_flag:
            if re.match('R', tcp_flag):
                return

        # Packet request (first)
        if packet_type == 'request' and not packet in data_request:

            data_request[packet] = {}
            data_request[packet]['timestamp'] = timet
            data_request[packet]['time'] = timeh
            data_request[packet]['ip'] = packet
            data_request[packet]['content'] = content
            data_request[packet]['count'] = 1

            # FEATURE AND EXTRA : MYSQL
            if service == 'mysql':
                m = re.search(r'^\S{5}([\w]{3,})', content.strip())
                if not m:
                    # CASE : db connect
                    n = re.search(r'^\S{36}([\w_-]{3,})', content.strip())
                    if n:
                        data_request[packet]['mysql_command'] = 'CONNECT WITH %s' % n.group(1)
                    else:
                        #print "#DEBUG# REQUEST MYSQL NOT RECOGNIZED : %s" % content
                        return
                else:
                    mysql_command = m.group(1)
                    if re.match('^(SHOW|SELECT|UPDATE|DELETE|INSERT|SET|COMMIT|ROLLBACK|CREATE|DROP|ALTER)$',
                                mysql_command, re.IGNORECASE):
                        data_request[packet]['mysql_command'] = m.group(1).upper()
            #######

            # EXTRA : http
            if service == 'http':
                m = re.search(r'Host: ([\w._-]*)\%s' % non_printable_char, content, re.DOTALL)
                if m:
                    data_request[packet]['http_host'] = m.group(1).lower()
                m = re.search(r'[GET|POST|PUT] (\S+) HTTP/[\d\.]+\%s' % non_printable_char, content, re.DOTALL)
                if m:
                    data_request[packet]['http_uri_level1'] = m.group(1).lower().split('/')[1].split('?')[0]
            #######

        # Packet request (others)
        elif packet_type == 'request' and packet in data_request:
            data_request[packet]['content'] = "%s%s" % (data_request[packet]['content'], content)
            data_request[packet]['count'] = data_request[packet]['count'] + 1
        # Packet response
        elif packet_type == 'response' and packet_reverse in data_request:
            duration = timet - data_request[packet_reverse]['timestamp']
            if not protocol in stat:
                stat[protocol] = {}
            if not service in stat[protocol]:
                stat[protocol][service] = {}
            if not 'duration' in stat[protocol][service]:
                stat[protocol][service]['duration'] = 0
                stat[protocol][service]['counter'] = 0
                stat[protocol][service]['max'] = 0
            stat[protocol][service]['duration'] += duration
            stat[protocol][service]['counter'] += 1
            if stat[protocol][service]['max'] < duration:
                stat[protocol][service]['max'] = duration
            data = {}
            data['request'] = data_request[packet_reverse]
            del data_request[packet_reverse]
            data['response'] = {}

            # EXTRA : MYSQL
            if service == 'mysql':
                if 'mysql_command' in data['request']:
                    mysql_command = data['request']['mysql_command']
                    mysql_command_select = None
                    if mysql_command == 'SELECT':
                        database = 'unknown'
                        table = 'unknown'
                        m = re.match(r'^[\S\n]{9,10}def%s?(\w+)%s(\w+)[\S\n]' % (non_printable_char,
                                                                                 non_printable_char), content.strip())
                        if m:
                            database = m.group(1)
                            table = m.group(2)
                            mysql_command_select = '%s.%s' % (database, table)
                    if not 'mysql' in extra:
                        extra['mysql'] = {}
                    if not 'command' in extra['mysql']:
                        extra['mysql']['command'] = {}
                    if not mysql_command in extra['mysql']['command']:
                        extra['mysql']['command'][mysql_command] = {}
                    if not 'count' in extra['mysql']['command'][mysql_command]:
                        extra['mysql']['command'][mysql_command]['count'] = 0
                        extra['mysql']['command'][mysql_command]['duration'] = 0
                        extra['mysql']['command'][mysql_command]['max'] = 0
                    extra['mysql']['command'][mysql_command]['count'] += 1
                    extra['mysql']['command'][mysql_command]['duration'] += duration
                    if extra['mysql']['command'][mysql_command]['max'] < duration:
                        extra['mysql']['command'][mysql_command]['max'] = duration
                    if mysql_command_select:
                        if not 'select' in extra['mysql']:
                            extra['mysql']['select'] = {}
                        if not mysql_command_select in extra['mysql']['select']:
                            extra['mysql']['select'][mysql_command_select] = {}
                        if not 'count' in extra['mysql']['select'][mysql_command_select]:
                            extra['mysql']['select'][mysql_command_select]['count'] = 0
                            extra['mysql']['select'][mysql_command_select]['duration'] = 0
                            extra['mysql']['select'][mysql_command_select]['max'] = 0
                        extra['mysql']['select'][mysql_command_select]['count'] += 1
                        extra['mysql']['select'][mysql_command_select]['duration'] += duration
                        if extra['mysql']['select'][mysql_command_select]['max'] < duration:
                            extra['mysql']['select'][mysql_command_select]['max'] = duration
            #######

            # EXTRA : http
            if service == 'http':
                m = re.search(r'HTTP\/1\.[012] ([\w\d\s]+)', content)
                if m:
                    status_code = m.group(1)
                    data['response']['status_code'] = status_code
                    if 'http_host' in data['request']:
                        host = data['request']['http_host']
                        if not 'http' in extra:
                            extra['http'] = {}
                        if not 'host' in extra['http']:
                            extra['http']['host'] = {}
                        if not host in extra['http']['host']:
                            extra['http']['host'][host] = {}
                        if not status_code in extra['http']['host'][host]:
                            extra['http']['host'][host][status_code] = {}
                        if not 'count' in extra['http']['host'][host][status_code]:
                            extra['http']['host'][host][status_code]['count'] = 0
                            extra['http']['host'][host][status_code]['duration'] = 0
                            extra['http']['host'][host][status_code]['max'] = 0
                        extra['http']['host'][host][status_code]['count'] += 1
                        extra['http']['host'][host][status_code]['duration'] += duration
                        if extra['http']['host'][host][status_code]['max'] < duration:
                            extra['http']['host'][host][status_code]['max'] = duration
                    if 'http_uri_level1' in data['request'] and 'http_host' in data['request']:
                        host_uri_level1 = '%s/%s' % (data['request']['http_host'], data['request']['http_uri_level1'])
                        if not 'http' in extra:
                            extra['http'] = {}
                        if not 'uri_level1' in extra['http']:
                            extra['http']['uri_level1'] = {}
                        if not host_uri_level1 in extra['http']['uri_level1']:
                            extra['http']['uri_level1'][host_uri_level1] = {}
                        if not status_code in extra['http']['uri_level1'][host_uri_level1]:
                            extra['http']['uri_level1'][host_uri_level1][status_code] = {}
                        if not 'count' in extra['http']['uri_level1'][host_uri_level1][status_code]:
                            extra['http']['uri_level1'][host_uri_level1][status_code]['count'] = 0
                            extra['http']['uri_level1'][host_uri_level1][status_code]['duration'] = 0
                            extra['http']['uri_level1'][host_uri_level1][status_code]['max'] = 0
                        extra['http']['uri_level1'][host_uri_level1][status_code]['count'] += 1
                        extra['http']['uri_level1'][host_uri_level1][status_code]['duration'] += duration
                        if extra['http']['uri_level1'][host_uri_level1][status_code]['max'] < duration:
                            extra['http']['uri_level1'][host_uri_level1][status_code]['max'] = duration
            #######

            # Matching duration filter
            if duration < duration_threshold:
                if filter_match:
                    return
            elif color and duration_threshold > 0:
                duration_color = green_background

            data['response']['time'] = timeh
            data['response']['ip'] = packet
            data['response']['content'] = content
            data['duration'] = duration
            data['protocol'] = protocol
            data['service'] = service

            # Matching regex filter
            matching = {}
            if regex_match['request'] or regex_match['response']:
                if ignore_case_match:
                    search_flags = re.DOTALL | re.IGNORECASE
                    sub_flags = re.IGNORECASE
                else:
                    search_flags = re.DOTALL
                    sub_flags = None

            for packet_type in regex_match:
                csize = content_size[packet_type]
                if regex_match[packet_type]:
                    matching[packet_type] = False
                    m = re.search('(%s)' % regex_match[packet_type], data[packet_type]['content'],
                                  flags=search_flags)
                    if m:
                        matching[packet_type] = True
                        if color:
                            regex = re.compile('(%s)' % regex_match[packet_type])
                            if sub_flags:
                                regex = re.compile('(%s)' % regex_match[packet_type], flags=sub_flags)
                            data[packet_type]['content'] = regex.sub(r'%s\g<1>%s' % (matching_color, reset_color),
                                                                     data[packet_type]['content'][:csize])

            if filter_match and (regex_match['request'] or regex_match['response']):
                if regex_match['request'] and regex_match['response']:
                    if regex_match['request'] == regex_match['response']:
                        if not matching['request'] and not matching['response']:
                            return
                    else:
                        if not matching['request'] or not matching['response']:
                            return
                elif regex_match['request'] and not regex_match['response']:
                    if not matching['request']:
                        return
                elif not regex_match['request'] and regex_match['response']:
                    if not matching['response']:
                        return

                if not protocol in stat_matched:
                    stat_matched[protocol] = {}
                if not service in stat_matched[protocol]:
                    stat_matched[protocol][service] = {}
                if not 'duration' in stat_matched[protocol][service]:
                    stat_matched[protocol][service]['duration'] = 0
                    stat_matched[protocol][service]['counter'] = 0
                    stat_matched[protocol][service]['max'] = 0
                stat_matched[protocol][service]['duration'] += duration
                stat_matched[protocol][service]['counter'] += 1
                if stat_matched[protocol][service]['max'] < duration:
                    stat_matched[protocol][service]['max'] = duration

            # Translate IP if asked
            if translate_ip:
                try:
                    if ip_src in dns_cache:
                        host_src = dns_cache[ip_src]
                    else:
                        start = time.time()
                        host_src = socket.gethostbyaddr(ip_src)[0]
                        finish = time.time()
                        if (finish - start) > dns_lookup_time_limit:
                            translate_ip = False
                        else:
                            dns_cache[ip_src] = host_src
                except socket.error:
                    host_src = "unknown"
                    dns_cache[ip_src] = host_src
                try:
                    if ip_dst in dns_cache:
                        host_dst = dns_cache[ip_dst]
                    else:
                        start = time.time()
                        host_dst = socket.gethostbyaddr(ip_dst)[0]
                        finish = time.time()
                        if (finish - start) > dns_lookup_time_limit:
                            translate_ip = False
                        else:
                            dns_cache[ip_dst] = host_dst
                except socket.error:
                    host_dst = "unknown"
                    dns_cache[ip_dst] = host_dst

            if content_size['request']:
                data['request']['content'] = data['request']['content'][:content_size['request']]
            if content_size['response']:
                data['response']['content'] = data['response']['content'][:content_size['response']]

            # Display
            if view == 'pretty':
                print bar_color + "/*" + "-" * 40 + "*/" + reset_color
                print
                if translate_ip:
                    print "%ssource%s      : %s (%s)" % (desc_color2, reset_color, dst, host_dst)
                    print "%sdestination%s : %s (%s)" % (desc_color2, reset_color, src, host_src)
                else:
                    print "%ssource%s      : %s" % (desc_color2, reset_color, dst)
                    print "%sdestination%s : %s" % (desc_color2, reset_color, src)
                print "%sservice%s     : %s (%s)" % (desc_color2, reset_color, service, protocol)
                print "%sstart time%s  : %s" % (desc_color2, reset_color, data['request']['time'])
                print "%send time%s    : %s" % (desc_color2, reset_color, timeh)
                print "%sduration%s    : %s%0.5f%ss" % (desc_color2, reset_color, duration_color, duration,
                                                        reset_color)
                print
                print " " + "-" * 17
                print "| %srequest content%s |" % (desc_color1, reset_color)
                print " " + "-" * 17
                print data['request']['content']
                if not no_display_response_content:
                    print " " + "-" * 18
                    print "| %sresponse content%s |" % (desc_color1, reset_color)
                    print " " + "-" * 18
                    print data['response']['content']
                print
            elif view == 'batch':
                print ";;;;%s;;;;%s;;;;%s;;;;%s;;;;%s;;;;%s%0.5f%s;;;;%s;;;;%s" % (dst, src, service,
                                                                                   data['request']['time'], timeh,
                                                                                   duration_color, duration,
                                                                                   reset_color,
                                                                                   data['request']['content'],
                                                                                   data['response']['content'])
            else:
                print bar_color + "/*" + "-" * 40 + "*/" + reset_color
                print
                if translate_ip:
                    print "%s %s>%s %s (%s > %s)" % (dst, desc_color1, reset_color, src, host_dst, host_src)
                else:
                    print "%s %s>%s %s" % (dst, desc_color1, reset_color, src)
                print "%sservice%s  : %s (%s)" % (desc_color2, reset_color, service,  protocol)
                print "%sduration%s : %s%0.5f%ss" % (desc_color2, reset_color, duration_color, duration,
                                                     reset_color)
                print "%srequest%s (%s)" % (desc_color2, reset_color, data['request']['time'])
                print data['request']['content']
                if not no_display_response_content:
                    print "%sresponse%s (%s)" % (desc_color2, reset_color, timeh)
                    print data['response']['content']
                print

# MAIN
if __name__ == '__main__':

    # Check if user used is 'root'
    if os.getuid() != 0:
        print "\nerror : only root can use this script.\n"
        sys.exit(2)

    # Check if ngrep command is present
    if not subprocess.call(['which', 'ngrep'], stdout=subprocess.PIPE) == 0:
        print "\nerror : ngrep is not in the path or is not installed.\n"
        sys.exit(2)

    # Default arguments
    input_pcap_file = None
    output_pcap_file = None
    output_file = None
    non_printable_char = '%'
    by_line = False
    devices = None
    ngrep_filter = None
    duration_threshold = 0
    dns_lookup_time_limit = 0.01
    view = "normal"
    filter_match = False
    color = False
    translate_ip = False
    no_display_response_content = False
    content_size = {}
    content_size['request'] = None
    content_size['response'] = None
    regex_match = {}
    regex_match['request'] = None
    regex_match['response'] = None
    ngrep_interface = None
    ignore_case_match = False

    # Services not in /etc/services (syntax: 'U|T': 'service_name' where U=UDP and T=TCP)
    services_custom = {
        'T81': 'http',
        'T3307': 'mysql',
        'T8080': 'http',
        'T8081': 'http',
        'T61613': 'activemq',
        'T61616': 'activemq'
    }

    # Signals
    signal.signal(signal.SIGINT, signal_end)
    signal.signal(signal.SIGALRM, signal_end)
    signal.signal(signal.SIGTERM, signal_end)
    signal.signal(signal.SIGHUP, signal_end)

    # Initialization of data/timers/counters/caches
    start_time = datetime.now()
    data_request = {}
    stat = {}
    stat_matched = {}
    extra = {}
    dns_cache = {}
    text_block = None

    # Read arguments
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "hv:D:m:fctlS:iF:ld:I:O:", ["help", "view=", "duration-threshold=",
                                                                     "regex-match=", "filter-match", "color",
                                                                     "translate-ip", "by-line", "no-response-content",
                                                                     "content-size=", "request-content-size=",
                                                                     "response-content-size=", "ignore-case-match",
                                                                     "request-regex-match=", "response-regex-match=",
                                                                     "ngrep-filter=", "device=", "input-pcap-file=",
                                                                     "output-pcap-file="])
    except getopt.GetoptError as err:
        print "\nerror : %s\n" % err
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
        elif opt in ("-l", "--by-line"):
            by_line = True
        elif opt in ("-d", "--device"):
            devices = arg
        elif opt in ("-F", "--ngrep-filter"):
            ngrep_filter = arg
        elif opt in ("-v", "--view"):
            view = arg
        elif opt in ("-D", "--duration-threshold"):
            try:
                duration_threshold = float(arg)
            except ValueError:
                print "\nerror : bad type, '-D' or '--duration-threshold' must be a float\n"
                sys.exit(2)
        elif opt in ("-m", "--regex-match"):
            regex_match['request'] = arg
            regex_match['response'] = arg
        elif opt in ("--request-regex-match"):
            regex_match['request'] = arg
        elif opt in ("--response-regex-match"):
            regex_match['response'] = arg
        elif opt in ("-f", "--filter-match"):
            filter_match = True
        elif opt in ("-c", "--color"):
            color = True
        elif opt in ("-t", "--translate-ip"):
            translate_ip = True
        elif opt in ("-i", "--ignore-case-match"):
            ignore_case_match = True
        elif opt in ("--no-response-content"):
            no_display_response_content = True
        elif opt in ("-S", "--content-size"):
            try:
                content_size['response'] = int(arg)
                content_size['request'] = int(arg)
            except ValueError:
                print "\nerror : bad type, '-S' or '--content-size' must be an integer\n"
                sys.exit(2)
        elif opt == "--request-content-size":
            try:
                content_size['request'] = int(arg)
            except ValueError:
                print "\nerror : bad type, '--request-content-size' must be an integer\n"
                sys.exit(2)
        elif opt == "--response-content-size":
            try:
                content_size['response'] = int(arg)
            except ValueError:
                print "\nerror : bad type, '--response-content-size' must be an integer\n"
                sys.exit(2)
        elif opt in ("-I", "--input-pcap-file"):
            input_pcap_file = arg
            pcap_file = open(input_pcap_file, "rb")
            magic = pcap_file.read(8)[:4]
            pcap_file.close()
            if magic != '\xd4\xc3\xb2\xa1':
                print "\nerror : file %s is not a pcap file\n" % input_pcap_file
                sys.exit(2)
        elif opt in ("-O", "--output-pcap-file"):
            output_pcap_file = arg
    if (regex_match['request'] or regex_match['response']) and not (color or filter_match):
        print "\nerror : missing complementary argument for -m (--match)\n"
        sys.exit(2)
    if filter_match and not (regex_match['request'] or regex_match['response'] or duration_threshold):
        print "\nerror : missing matching arguments for -f (--filter-match)\n"
        sys.exit(2)
    if duration_threshold > 0 and not (color or filter_match):
        print "\nerror : missing complementary argument for -D (--duration-threshold)\n"
        sys.exit(2)

    # Variables for string colorization
    # http://misc.flogisoft.com/bash/tip_colors_and_formatting
    red_bold = '\x1b[1;31m'
    red_bold_underlined = '\x1b[1;4;31m'
    green_background = '\x1b[42m'
    blue_background = '\x1b[44m'
    grey_bold_background = '\x1b[1;100m'
    if color:
        matching_color = blue_background
        bar_color = grey_bold_background
        desc_color1 = red_bold
        desc_color2 = red_bold_underlined
        reset_color = '\x1b[0m'
    else:
        matching_color = ''
        bar_color = ''
        desc_color1 = ''
        desc_color2 = ''
        reset_color = ''

    # Header for 'batch' view
    if view == 'batch':
        print ";;;;dst;;;;src;;;;service;;;;start_time;;;;end_time;;;;duration;;;;request_content;;;;response_content"

    # Build arguments for ngrep command
    ngrep_filter_args = ['ngrep', '-qltWbyline', '-P%s' % non_printable_char]
    if input_pcap_file:
        ngrep_filter_args.append('-I%s' % input_pcap_file)
    if output_pcap_file:
        ngrep_filter_args.append('-O%s' % output_pcap_file)
    if devices:
        ngrep_filter_args.append('-d%s' % devices)
    if ngrep_filter:
        ngrep_filter_args += ['tcp', 'or', 'udp', 'and']
        for i in ngrep_filter.split():
            ngrep_filter_args.append(i)

    # Launch ngrep command
    proc = subprocess.Popen(ngrep_filter_args, stdout=subprocess.PIPE)

    # Loop until an exit by a signal
    while True:
        text_block = ""

        # Loop until a text block is identified
        for line in iter(proc.stdout.readline, ''):
            # Cleaning line return
            line = line.rstrip()
            # Pass empty line
            if line == "":
                break
            # Pass information line of ngrep
            if re.search(r'^(interface|filter|match):\s*.*', line):
                break
            # Insert return line if necessary
            if by_line and view != 'batch':
                text_block += "%s\n" % line
            else:
                text_block += "%s" % line
            # Check if ngrep command is alive (necessary for -I)
            if proc.poll() is not None:
                signal.alarm(1)

        # Processing text block
        process(text_block)
