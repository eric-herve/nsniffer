#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
nsniffer.py : Linux tcpdump wrapper.

Author  : Eric Herve <eric.herve.fr@gmail.com>

"""

import getopt
import os
import re
import signal
import socket
import subprocess
import sys
import time
import logging
from datetime import datetime


def usage():
    """Usage of this script."""

    print """
tcpdump wrapper (only ipv4 and tcp/udp).

Arguments:

# Filter :

  -d DEVICE, --devices DEVICE        By default tcpdump will select a default interface to listen on.
                                     Use this option to force tcpdump to listen on interface DEVICE
                                     ('any' for any devices).
  -F, --tcpdump-filter=FILTER        Filter layer 3/4. Use tcpdump filter (for details, see tcpdump manual).
  -E, --extra-filter=REGEX           Filter layer 7. Match with regex in the extra fields ('-f' and/or '-c' needed).
  -i, --ignore-case-match            Ignore case distinctions in matching.

# Display :

  -v NAME, --view=NAME               Display view ('normal', 'pretty' or 'batch', default: normal).
  -X, --extra                        Display extra statistics for any and matched requests.
  --extra-any                        Display extra statistics for any requests.
  --extra-matched                    Display extra statistics for matched requests.
  -l, --by-line                      Display content line by line.
  -f, --filter-match                 Display only the requests that are matched.
  -c, --color                        Active colorization (in particular with matching).
  -t, --translate-ip                 If possible, host lookup (warning: if lookup
                                     is too slow, it will be automaticaly disabled).
  -S SIZE, --content-size=SIZE       Limit the string size (display only) of content.
  --request-content-size=SIZE        Limit the string size (display only) of request content.
  --response-content-size=SIZE       Limit the string size (display only) of response content.
  --no-response-content              Don't display the request content (disabled in batch view).
  --apple-version                    Some versions of tcpdump on Apple systems need this argument.

# Display specifics extra statistics (only for http service) :

  --extra-http-uri-level1            Display extra statistics by uri (level1) ('--extra'* needed).

# Pcap :

  -I, --input-pcap=FILE              Input file pcap_dump into tcpdump ('-' from stdin).

# Help :

  --verbose                          Display verbose informations (critical, error, warning, info).
  --debug                            Display debug informations ('--verbose' + debug).
  -h, --help                         Display this help and exit.
"""

    print "Examples :"
    print
    print r"  # %s -d any -tlc --no-response-content" % script_name
    print r"  # %s -d any -Xlc -F 'host 1.2.3.4' -v pretty -f -E 'http_request_content \"GET|POST\"'" % script_name
    print r"  # %s -d any -Xtlc -F 'port 80' -v batch -f -E 'not http_status_code \"2\d{2}|3\d{2}\" and duration greater 1'" % script_name
    print r"  # %s -d any -Xtlc -f -E 'mysql_method \"INSERT\"' --response-content-size=50" % script_name
    print r"  # %s -d any -Xtlc -f -E 'service \"mysql\" and duration range 1.5-2.5'" % script_name
    print r"  # %s -d eth0 -X -f -E 'duration greater 2.5' -I /root/tcpdump.pcap" % script_name
    print r"  # tcpdump -B 4096 -s 2048 -UKl -w - | tee /root/tcpdump.pcap | %s -tlcX -I -" % script_name
    print
    sys.exit(2)


def display_stats(stats):
    """Print statistics informations."""

    for direction in sorted(stats):
        print "%*s- %s" % (stats_level1_length, '', direction)
        for protocol in sorted(stats[direction]):
            for service in sorted(stats[direction][protocol]):
                duration = stats[direction][protocol][service]['duration']
                counter = stats[direction][protocol][service]['counter']
                maximum = stats[direction][protocol][service]['max']
                service_port = stats[direction][protocol][service]['port']
                average = duration / counter
                print "%*s- %-15s (%s/%-6s) : %6s request(s) in %0.5fs (average: %0.5fs, max: %0.5fs)" % \
                      (stats_level2_length, ' ', service, protocol, service_port, counter, duration, average, maximum)


def display_extra_stats(extra_stats):
    """Print extra statistics informations."""

    for direction in sorted(extra_stats):
        print "%*s- %s" % (stats_level1_length, '', direction)
        for service in sorted(extra_stats[direction]):
            if re.match('http$|http_', service):
                print "%*s- %s" % (stats_level2_length, '', service)
                for name in sorted(extra_stats[direction][service]):
                    print "%*s- details by '%s'" % (stats_level3_length, '', name)
                    for http_host in sorted(extra_stats[direction][service][name]):
                        if not http_host:
                            print "%*s- None" % (stats_level4_length, ' ')
                        else:
                            print "%*s- 'http://%s'" % (stats_level4_length, ' ', http_host)
                        for http_status_code in sorted(extra_stats[direction][service][name][http_host]):
                            average = extra_stats[direction][service][name][http_host][http_status_code]['duration'] /\
                                extra_stats[direction][service][name][http_host][http_status_code]['count']
                            print "%*s- %-22s : %6s request(s) in %0.5fs (average: %0.5fs, max: %0.5fs)" \
                                % (stats_level5_length, ' ', http_status_code,
                                   extra_stats[direction][service][name][http_host][http_status_code]['count'],
                                   extra_stats[direction][service][name][http_host][http_status_code]['duration'],
                                   average,
                                   extra_stats[direction][service][name][http_host][http_status_code]['max'])
                            if 'http_varnish_caching' in extra_stats[direction][service][name][http_host][http_status_code]:
                                c = extra_stats[direction][service][name][http_host][http_status_code]['http_varnish_caching']
                                caching = 'http_varnish_caching={MISS:%s, HIT:%s, NOCACHE:%s}' % (c['MISS'],
                                                                                                  c['HIT'],
                                                                                                  c['NOCACHE'])
                                print "%43s %s" % (' ', caching)
            elif service == 'mysql':
                print "%*s- %s" % (stats_level2_length, '', service)
                for name in sorted(extra_stats[direction][service]):
                    print "%*s- details by '%s'" % (stats_level3_length, '', name)
                    for mysql_method in sorted(extra_stats[direction][service][name]):
                        average = extra_stats[direction][service][name][mysql_method]['duration'] / \
                            extra_stats[direction][service][name][mysql_method]['count']
                        if mysql_method:
                            mysql_method_size = len(mysql_method)
                        else:
                            mysql_method_size = 0
                        if mysql_method_size <= 24:
                            print "%*s- %-24s : %6s request(s) in %0.5fs (average: %0.5fs, max: %0.5fs)" \
                                % (stats_level4_length, ' ', mysql_method,
                                   extra_stats[direction][service][name][mysql_method]['count'],
                                   extra_stats[direction][service][name][mysql_method]['duration'], average,
                                   extra_stats[direction][service][name][mysql_method]['max'])
                        else:
                            print "%*s- %-24s :\n%37s%6s request(s) in %0.5fs (average: %0.5fs, max: %0.5fs)" \
                                % (stats_level4_length, ' ', mysql_method, ' ',
                                   extra_stats[direction][service][name][mysql_method]['count'],
                                   extra_stats[direction][service][name][mysql_method]['duration'], average,
                                   extra_stats[direction][service][name][mysql_method]['max'])


def display_full_stats():
    """Print statistics."""

    # Calculation of the capture duration
    capture_duration = 0
    stime = None
    ltime = None
    if first_time and last_time:
        try:
            # Convert human time in timestamp
            td = datetime.strptime(first_time, '%Y-%m-%d %H:%M:%S.%f') - datetime(1970, 1, 1)
            stime = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 1e6
            td = datetime.strptime(last_time, '%Y-%m-%d %H:%M:%S.%f') - datetime(1970, 1, 1)
            ltime = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 1e6
        except AttributeError:
            # Used in some CTRL + C
            return
        capture_duration = datetime.fromtimestamp(ltime) - datetime.fromtimestamp(stime)

    # Print time informations
    print
    print "Period"
    print
    print "#" * 66
    print "%-*s : %s" % (stats_title_length, 'First request', first_time)
    print "%-*s : %s" % (stats_title_length, 'Last request', last_time)
    print "%-*s : %s hour(s)" % (stats_title_length, 'Capture duration', capture_duration)
    print "#" * 66

    # Print parameters informations
    print
    print "Parameters"
    print
    print "#" * 66
    if input_pcap_file:
        print "%-*s : %s" % (stats_title_length, 'Input pcap file', input_pcap_file)
    if tcpdump_filter:
        print "%-*s : %s" % (stats_title_length, 'tcpdump filter (layer 3/4)', tcpdump_filter)
    if extra_filter:
        print "%-*s : %s" % (stats_title_length, 'Extra filter (layer 7)', extra_filter_args)
    if ignore_case_match:
        print "%-*s : %s" % (stats_title_length, 'Ignore case match', ignore_case_match)
    print "%-*s : %s" % (stats_title_length, 'View', view)
    if display_extra_global_stats:
        print "%-*s : %s" % (stats_title_length, 'Extra statistics of any requests', display_extra_global_stats)
    if display_extra_matched_stats:
        print "%-*s : %s" % (stats_title_length, 'Extra statistics of matched requests', display_extra_matched_stats)
    if by_line:
        print "%-*s : %s" % (stats_title_length, 'By line', by_line)
    if filter_match:
        print "%-*s : %s" % (stats_title_length, 'Filter', filter_match)
    if color:
        print "%-*s : %s" % (stats_title_length, 'Color', color)
    if translate_ip:
        print "%-*s : %s" % (stats_title_length, 'Translate IP', translate_ip)
    if 'request' in content_size:
        if content_size['response']:
            print "%-*s : %s" % (stats_title_length, 'Request content size', content_size['request'])
    if not display_response_content:
        print "%-*s : %s" % (stats_title_length, 'No response content display', 'True')
    else:
        if 'response' in content_size:
            if content_size['response']:
                print "%-*s : %s" % (stats_title_length, 'Response content size', content_size['response'])
    print "#" * 66

    # Print first statistic title
    if global_stats or matched_stats or extra_global_stats or extra_matched_stats:
        print
        print "#" * 10
        print "STATISTICS"
        print "#" * 10

    # Print GLOBAL statistic title
    if global_stats or (extra_global_stats and display_extra_global_stats):
        print
        print "-" * 12
        print "ANY requests"
        print "-" * 12

        # Print GLOBAL statistic informations
        if global_stats:
            print
            print "- Number of requests and response time by service :"
            display_stats(global_stats)

        # Print extra GLOBAL statistic informations
        if extra_global_stats and display_extra_global_stats:
            print
            print "- Extra stats by service :"
            display_extra_stats(extra_global_stats)

    # Print MATCHED statistic title
    if filter_match and (matched_stats or (extra_matched_stats and display_extra_matched_stats)):
        print
        print "-" * 16
        print "MATCHED requests"
        print "-" * 16

        # Print MATCHED statistic informations
        if matched_stats and filter_match:
            print
            print "- Number of requests and response time by service :"
            display_stats(matched_stats)

        # Print extra MATCHED statistic informations
        if extra_matched_stats and display_extra_matched_stats:
            print
            print "- Extra stats by service :"
            display_extra_stats(extra_matched_stats)

    print


def process():
    """Consolidate data packets."""

    ###
    # MYSQL functions
    ###

    def get_mysql_extra_infos():
        """Extract mysql extra informations for statistics."""

        if service == 'mysql':
            data['mysql_method'] = None
            m = re.search(r'^.{5,8}(?P<method>SHOW|SELECT|UPDATE|DELETE|INSERT|SET|COMMIT|ROLLBACK|CREATE|DROP|ALTER|START)',
                          data['request_content'], re.IGNORECASE | re.DOTALL)
            if m:
                # CASE : method
                data['mysql_method'] = m.group('method').upper()
            else:
               # CASE : db connect
                m = re.search(r'^.{36}(?P<user>[\w_-]{3,})', data['request_content'].strip())
                if m:
                    data['mysql_method'] = 'CONNECT WITH USER \'%s\'' % m.group('user')
                else:
                    m = re.search(r'^[\s.]{4,5}(?P<name>[\w_-]{2,})(?P<database_type>\.|)[\\n]*$',
                                  data['request_content'].strip())
                    if m:
                        if not m.group('database_type'):
                            data['mysql_method'] = 'CONNECT TO DATABASE \'%s\'' % m.group('name')
                        else:
                            data['mysql_method'] = 'CONNECT TO TABLE'
                    else:
                        data['request_content'] = data['request_content'][:256]
                        logging.error('### MYSQL REQUEST NOT RECOGNIZED : %s ###', data)

    def process_mysql_extra(extra_stats):
        """Process mysql extra statistics."""

        if service == 'mysql':
            if 'mysql_method' in data:
                mysql_method = data['mysql_method']
                if not direction in extra_stats:
                    extra_stats[direction] = {}
                if not 'mysql' in extra_stats[direction]:
                    extra_stats[direction]['mysql'] = {}
                if not 'mysql_method' in extra_stats[direction]['mysql']:
                    extra_stats[direction]['mysql']['mysql_method'] = {}
                if not mysql_method in extra_stats[direction]['mysql']['mysql_method']:
                    extra_stats[direction]['mysql']['mysql_method'][mysql_method] = {}
                if not 'count' in extra_stats[direction]['mysql']['mysql_method'][mysql_method]:
                    extra_stats[direction]['mysql']['mysql_method'][mysql_method]['count'] = 0
                    extra_stats[direction]['mysql']['mysql_method'][mysql_method]['duration'] = 0
                    extra_stats[direction]['mysql']['mysql_method'][mysql_method]['max'] = 0
                extra_stats[direction]['mysql']['mysql_method'][mysql_method]['count'] += 1
                extra_stats[direction]['mysql']['mysql_method'][mysql_method]['duration'] += duration
                if extra_stats[direction]['mysql']['mysql_method'][mysql_method]['max'] < duration:
                    extra_stats[direction]['mysql']['mysql_method'][mysql_method]['max'] = duration

    ###
    # HTTP functions
    ###

    def get_http_extra_infos():
        """Extract http extra informations for statistics."""

        if re.match('http$|http_', service):
            data['http_host'] = ''
            data['http_host_uri_level1'] = ''
            data['http_status_code'] = ''
            m = re.search(r'Host: (?P<host>[\d\w\:._-]*)\s*\n*', data['request_content'])
            if m:
                data['http_host'] = m.group('host').lower()

            if display_extra_http_host_uri_level1:
                m = re.search(r'(?:GET|POST|PUT|HEAD|DELETE) (?P<uri>\S+)(?: HTTP/[\d\.]+|)',
                              data['request_content'])
                if m:
                    if re.search(r'/', m.group('uri')):
                        uri_level1 = m.group('uri').lower().split('/')[1].split('?')[0]
                        data['http_host_uri_level1'] = '%s/%s' % (data['http_host'], uri_level1)

            m = re.search(r'HTTP/[\d.]+ (?P<status_code>\d+) ', data['response_content'])
            if m:
                data['http_status_code'] = m.group('status_code')
                if re.search(r'X-Varnish: \d+ \d+', data['response_content'], re.DOTALL):
                    data['http_varnish_caching'] = 'HIT'
                elif re.search(r'X-Varnish: \d+', data['response_content'], re.DOTALL):
                    data['http_varnish_caching'] = 'MISS'
            else:
                data['response_content'] = data['response_content'][:256]

    def process_http_extra(extra_stats):
        """Process http extra statistics."""

        if re.match('http$|http_', service):
            http_status_code = data['http_status_code']
            http_host_level = ['http_host']
            if display_extra_http_host_uri_level1:
                http_host_level.append('http_host_uri_level1')
            for name in http_host_level:
                if name in data:
                    http_host = data[name]
                    if not direction in extra_stats:
                        extra_stats[direction] = {}
                    if not service in extra_stats[direction]:
                        extra_stats[direction][service] = {}
                    if not name in extra_stats[direction][service]:
                        extra_stats[direction][service][name] = {}
                    if not http_host in extra_stats[direction][service][name]:
                        extra_stats[direction][service][name][http_host] = {}
                    if not http_status_code in extra_stats[direction][service][name][http_host]:
                        extra_stats[direction][service][name][http_host][http_status_code] = {}
                    if not 'count' in extra_stats[direction][service][name][http_host][http_status_code]:
                        extra_stats[direction][service][name][http_host][http_status_code]['count'] = 0
                        extra_stats[direction][service][name][http_host][http_status_code]['duration'] = 0
                        extra_stats[direction][service][name][http_host][http_status_code]['max'] = 0
                    extra_stats[direction][service][name][http_host][http_status_code]['count'] += 1
                    extra_stats[direction][service][name][http_host][http_status_code]['duration'] += duration
                    if extra_stats[direction][service][name][http_host][http_status_code]['max'] < duration:
                        extra_stats[direction][service][name][http_host][http_status_code]['max'] = duration
                    if 'http_varnish_caching' in data:
                        if not 'http_varnish_caching' in extra_stats[direction][service][name][http_host][http_status_code]:
                            extra_stats[direction][service][name][http_host][http_status_code]['http_varnish_caching'] = {}
                            extra_stats[direction][service][name][http_host][http_status_code]['http_varnish_caching']['MISS'] = 0
                            extra_stats[direction][service][name][http_host][http_status_code]['http_varnish_caching']['HIT'] = 0
                            extra_stats[direction][service][name][http_host][http_status_code]['http_varnish_caching']['NOCACHE'] = 0
                        if data['http_varnish_caching'] == 'MISS':
                            extra_stats[direction][service][name][http_host][http_status_code]['http_varnish_caching']['MISS'] += 1
                        if data['http_varnish_caching'] == 'HIT':
                            extra_stats[direction][service][name][http_host][http_status_code]['http_varnish_caching']['HIT'] += 1
                    else:
                        if 'http_varnish_caching' in extra_stats[direction][service][name][http_host][http_status_code]:
                            extra_stats[direction][service][name][http_host][http_status_code]['http_varnish_caching']['NOCACHE'] += 1

    global first_time
    global last_time
    global translate_ip

    ###
    # Process packet
    ###

    # Extract protocol
    protocol = packet_info['protocol']

    # Skip empty packets
    if protocol == 'TCP':
        if 'length_data' in packet_info:
            if packet_info['length_data'] == 0:
                return

    # Extract time
    timeh = packet_info['time']
    try:
        # Convert human time in timestamp
        td = datetime.strptime(timeh, '%Y-%m-%d %H:%M:%S.%f') - datetime(1970, 1, 1)
        timet = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 1e6
    except AttributeError:
        # Used in some CTRL + C
        return
    if not first_time:
        first_time = timeh
    last_time = timeh

    # Extract packet source and destination
    ip_src = packet_info['ip_src']
    port_src = packet_info['port_src']
    src = "%s:%i" % (ip_src, port_src)
    ip_dst = packet_info['ip_dst']
    port_dst = packet_info['port_dst']
    dst = "%s:%i" % (ip_dst, port_dst)
    packet_id = "%s -> %s" % (src, dst)
    packet_id_reverse = "%s -> %s" % (dst, src)

    # Extract begin position in content (to skip headers)
    if protocol == 'TCP':
        begin_pos = 0
        if 'length_data' in packet_info:
            if apple_version and (input_pcap_file == '-' or not input_pcap_file):
                begin_pos = packet_info['length_ip'] - packet_info['length_data']
            else:
                begin_pos = packet_info['length_tcp'] - packet_info['length_data']
            returnline_count = packet_info['content'][:begin_pos].count('\n')
            begin_pos = begin_pos + returnline_count
        content = packet_info['content'][begin_pos:]
    else:
        content = packet_info['content']

    # Extract service name
    service_src = None
    service_dst = None
    if port_src in services_cache[protocol]:
        service_src = services_cache[protocol][port_src]
    elif port_dst in services_cache[protocol]:
        service_dst = services_cache[protocol][port_dst]
    elif '%s%s' % (protocol, port_src) in services_custom:
        service_src = services_custom['%s%s' % (protocol, port_src)]
        services_cache[protocol][port_src] = service_src
    elif '%s%s' % (protocol, port_dst) in services_custom:
        service_dst = services_custom['%s%s' % (protocol, port_dst)]
        services_cache[protocol][port_dst] = service_dst
    else:
        try:
            service_src = socket.getservbyport(port_src, protocol.lower())
            services_cache[protocol][port_src] = service_src
        except socket.error:
            service_src = None
        except OverflowError:
            service_src = None
        if not service_src:
            try:
                service_dst = socket.getservbyport(port_dst, protocol.lower())
                services_cache[protocol][port_dst] = service_dst
            except socket.error:
                service_dst = None
            except OverflowError:
                service_dst = None

    # Extract packet type (request or response) and service
    service_port = None
    if service_src and service_dst:
        if port_src < port_dst:
            service_dst = None
        else:
            service_src = None
    if not service_src and not service_dst:
        if port_src < port_dst:
            service_src = str(port_src)
        else:
            service_dst = str(port_dst)
    if service_src and not service_dst:
        packet_type = "response"
        service = service_src
        service_port = port_src
        packet_id = packet_id_reverse
        ip_src, port_src, src, ip_dst, port_dst, dst = ip_dst, port_dst, dst, ip_src, port_src, src
    elif not service_src and service_dst:
        packet_type = "request"
        service = service_dst
        service_port = port_dst
    # Request packet unknown
    if not packet_type:
        logging.error('### BUG - PACKET TYPE IS UNKNOWN : %s ###', packet_info)
        return
    # Rename 'www' service in 'http'
    if service == 'www':
        service = 'http'
    packet_info['service_name'] = service
    packet_info['service_port'] = service_port

    # Request packets process
    if packet_type == 'request':

        # Extract packet direction
        if 'direction' in packet_info:
            direction = packet_info['direction']
        else:
            if input_pcap_file:
                direction = 'UNKNOWN DIRECTION'
            else:
                direction = 'ROUTING'
            if ip_src in local_ip:
                direction = 'OUTPUT'
            if ip_dst in local_ip:
                if direction == 'OUTPUT':
                    direction = 'LOCAL'
                else:
                    direction = 'INPUT'
            packet_info['direction'] = direction

        # Skip mysql packet empty
        if service == 'mysql':
            if re.search(r'^\.+$', content.strip()):
                return

        # First request packet
        if not packet_id in response_packets_info:
            if not packet_id in request_packets_info:
                request_packets_info[packet_id] = {}
                request_packets_info[packet_id]['service'] = service
                request_packets_info[packet_id]['direction'] = direction
                request_packets_info[packet_id]['protocol'] = protocol
                request_packets_info[packet_id]['request_timestamp'] = timet
                request_packets_info[packet_id]['request_time'] = timeh
                request_packets_info[packet_id]['request_content'] = content
                logging.debug('### INSERT REQUEST : %s ###', packet_id)
            # Others request packets
            elif protocol == 'TCP':
                request_packets_info[packet_id]['request_content'] += content
                logging.debug('### APPEND REQUEST : %s ###', packet_id)
            else:
                logging.debug('### PACKET REQUEST EXIST WITH NO RESPONSE : %s ###', packet_info)
        else:
            logging.debug('### PACKET RESPONSE EXIST WITH NO REQUEST : %s ###', packet_info)

        if debug:
            logging.debug('### LIST OF ALL CURRENT REQUESTS ###')
            if request_packets_info:
                for j in sorted(request_packets_info.keys()):
                    logging.debug('%s', j)
            else:
                logging.debug('None')
            logging.debug('###############')

    # Response packets process
    elif packet_type == 'response':

        # Exclude unused response packets
        if not packet_id in request_packets_info:
            return

        # First response packet
        if not packet_id in response_packets_info:
            response_packets_info[packet_id] = {}
            response_packets_info[packet_id]['response_timestamp'] = timet
            response_packets_info[packet_id]['response_time'] = timeh
            response_packets_info[packet_id]['response_content'] = content
            logging.debug("### INSERT RESPONSE : %s ###", packet_id)
        # Others response packets (not used because already exclude)
        else:
            logging.debug('### ALREADY A RESPONSE FOR THE REQUEST : %s ###', packet_id)

        if debug:
            logging.debug('### LIST OF ALL CURRENT RESPONSES ###')
            if response_packets_info:
                for j in sorted(response_packets_info.keys()):
                    logging.debug('%s', j)
            else:
                logging.debug('None')
            logging.debug('###############')

    # Assemble request and response
    if (packet_id in request_packets_info and packet_id in response_packets_info):

        logging.debug("### ASSEMBLE REQUEST AND RESPONSE : %s ###", packet_id)

        data = {}
        data = request_packets_info[packet_id]
        del request_packets_info[packet_id]

        logging.debug("### DELETE REQUEST : %s ###", packet_id)
        if debug:
            logging.debug('### LIST OF ALL CURRENT REQUESTS ###')
            if request_packets_info:
                for j in sorted(request_packets_info.keys()):
                    logging.debug('%s', j)
            else:
                logging.debug('None')
            logging.debug('###############')

        data.update(response_packets_info[packet_id])
        del response_packets_info[packet_id]

        logging.debug("### DELETE RESPONSE : %s ###", packet_id)
        if debug:
            logging.debug('### LIST OF ALL CURRENT RESPONSES ###')
            if response_packets_info:
                for j in sorted(response_packets_info.keys()):
                    logging.debug('%s', j)
            else:
                logging.debug('None')
            logging.debug('################')

        if display_extra_global_stats or display_extra_matched_stats:

            ## EXTRA INFORMATIONS ##
            # infos : mysql
            get_mysql_extra_infos()
            #######
            # infos : http
            get_http_extra_infos()
            #######

        direction = data['direction']
        duration = data['response_timestamp'] - data['request_timestamp']
        data['duration'] = '%0.5f' % duration
        if not direction in global_stats:
            global_stats[direction] = {}
        if not protocol in global_stats[direction]:
            global_stats[direction][protocol] = {}
        if not service in global_stats[direction][protocol]:
            global_stats[direction][protocol][service] = {}
        if not 'duration' in global_stats[direction][protocol][service]:
            global_stats[direction][protocol][service]['duration'] = 0
            global_stats[direction][protocol][service]['counter'] = 0
            global_stats[direction][protocol][service]['max'] = 0
            global_stats[direction][protocol][service]['port'] = service_port
        global_stats[direction][protocol][service]['duration'] += duration
        global_stats[direction][protocol][service]['counter'] += 1
        if global_stats[direction][protocol][service]['max'] < duration:
            global_stats[direction][protocol][service]['max'] = duration

        if display_extra_global_stats:

            ## EXTRA PROCESS ##
            # process : mysql
            process_mysql_extra(extra_global_stats)
            #######
            # process : http
            process_http_extra(extra_global_stats)
            #######

        # Matching regex filter
        if ignore_case_match:
            search_flags = re.DOTALL | re.IGNORECASE
            sub_flags = re.IGNORECASE
        else:
            search_flags = re.DOTALL
            sub_flags = None

        if extra_filter:
            for f in extra_filter:
                negative = False
                color_select = matching_color
                g = re.match(extra_filter_regex, f)
                if g:
                    if g.group('negative'):
                        negative = True
                        color_select = not_matching_color
                    if g.group('std_field') in data:
                        if filter_match:
                            if negative:
                                if re.search(r'%s' % g.group('std_regex'), data[g.group('std_field')], search_flags):
                                    return
                            else:
                                if not re.search(r'%s' % g.group('std_regex'), data[g.group('std_field')], search_flags):
                                    return
                        if color:
                            reg = re.compile('(?P<matching_str>%s)' % g.group('std_regex'))
                            if sub_flags:
                                reg = re.compile('(?P<matching_str>%s)' % g.group('std_regex'), sub_flags)
                            data[g.group('std_field')] = reg.sub(r'%s\g<matching_str>%s' % (color_select, reset_color),
                                                                 data[g.group('std_field')])
                    elif g.group('greater_field'):
                        if filter_match:
                            if negative:
                                if float(g.group('greater_min')) <= float(data[g.group('greater_field')]):
                                    return
                            else:
                                if not float(g.group('greater_min')) <= float(data[g.group('greater_field')]):
                                    return
                        if color:
                            reg = re.compile('(?P<matching_str>.+)')
                            data[g.group('greater_field')] = '%s%s%s' % (color_select, data[g.group('greater_field')],
                                                                         reset_color)
                    elif g.group('less_field'):
                        if filter_match:
                            if negative:
                                if float(g.group('less_max')) >= float(data[g.group('less_field')]):
                                    return
                            else:
                                if not float(g.group('less_max')) >= float(data[g.group('less_field')]):
                                    return
                        if color:
                            reg = re.compile('(?P<matching_str>.+)')
                            data[g.group('less_field')] = '%s%s%s' % (color_select, data[g.group('less_field')],
                                                                      reset_color)
                    elif g.group('range_field'):
                        if float(g.group('range_min')) >= float(g.group('range_max')):
                            print >> sys.stderr, "\nERROR : bad range.\n"
                            sys.exit(2)
                        if filter_match:
                            if negative:
                                if float(g.group('range_min')) <= float(data[g.group('range_field')]) <= float(g.group('range_max')):
                                    return
                            else:
                                if not float(g.group('range_min')) <= float(data[g.group('range_field')]) <= float(g.group('range_max')):
                                    return
                        if color:
                            reg = re.compile('(?P<matching_str>.+)')
                            data[g.group('range_field')] = '%s%s%s' % (color_select, data[g.group('range_field')],
                                                                       reset_color)
                    else:
                        return
                else:
                    print >> sys.stderr, "\nERROR : bad regular expression.\n"
                    sys.exit(2)

        if display_extra_matched_stats:

            ## EXTRA PROCESS ##
            # process : mysql
            process_mysql_extra(extra_matched_stats)
            #######
            # process : http
            process_http_extra(extra_matched_stats)
            #######

            if not direction in matched_stats:
                matched_stats[direction] = {}
            if not protocol in matched_stats[direction]:
                matched_stats[direction][protocol] = {}
            if not service in matched_stats[direction][protocol]:
                matched_stats[direction][protocol][service] = {}
            if not 'duration' in matched_stats[direction][protocol][service]:
                matched_stats[direction][protocol][service]['duration'] = 0
                matched_stats[direction][protocol][service]['counter'] = 0
                matched_stats[direction][protocol][service]['max'] = 0
                matched_stats[direction][protocol][service]['port'] = service_port
            matched_stats[direction][protocol][service]['duration'] += duration
            matched_stats[direction][protocol][service]['counter'] += 1
            if matched_stats[direction][protocol][service]['max'] < duration:
                matched_stats[direction][protocol][service]['max'] = duration

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
                        logging.info('### IP TRANSLATION DISABLED ####')
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
                        logging.info('### IP TRANSLATION DISABLED ####')
                    else:
                        dns_cache[ip_dst] = host_dst
            except socket.error:
                host_dst = "unknown"
                dns_cache[ip_dst] = host_dst

        # Reduce content size
        if content_size['request']:
            data['request_content'] = data['request_content'][:content_size['request']]
        if content_size['response']:
            data['response_content'] = data['response_content'][:content_size['response']]

        # Escape return line if necessary
        if not by_line or view == 'batch':
            data['request_content'] = data['request_content'].replace('\n', '\\n')
            data['response_content'] = data['response_content'].replace('\n', '\\n')

        # Display request/response informations
        if view == 'pretty':
            print bar_color + "/*" + "-" * 40 + "*/" + reset_color
            print
            print "%sdirection%s            : %s" % (desc_color2, reset_color, data['direction'])
            if translate_ip:
                print "%ssource%s               : %s (%s)" % (desc_color2, reset_color, src, host_src)
                print "%sdestination%s          : %s (%s)" % (desc_color2, reset_color, dst, host_dst)
            else:
                print "%ssource%s               : %s" % (desc_color2, reset_color, src)
                print "%sdestination%s          : %s" % (desc_color2, reset_color, dst)
            print "%sservice%s              : %s (%s)" % (desc_color2, reset_color, data['service'], data['protocol'])
            print "%srequest time%s         : %s" % (desc_color2, reset_color, data['request_time'])
            print "%sresponse time%s        : %s" % (desc_color2, reset_color, data['response_time'])
            print "%sduration%s             : %ss" % (desc_color2, reset_color, data['duration'])
            if 'http_host' in data:
                if data['http_host']:
                    print "%shttp_host%s            : %s" % (desc_color3, reset_color,
                                                             data['http_host'])
            if 'http_status_code' in data:
                if data['http_status_code']:
                    print "%shttp status code%s     : %s" % (desc_color3, reset_color,
                                                             data['http_status_code'])
            if 'http_varnish_caching' in data:
                if data['http_varnish_caching']:
                    print "%shttp varnish caching%s : %s" % (desc_color3, reset_color,
                                                             data['http_varnish_caching'])
            if 'mysql_method' in data:
                if data['mysql_method']:
                    print "%smysql method%s         : %s" % (desc_color3, reset_color,
                                                             data['mysql_method'])
            print
            print " " + "-" * 17
            print "| %srequest content%s |" % (desc_color1, reset_color)
            print " " + "-" * 17
            print data['request_content']
            if display_response_content:
                print " " + "-" * 18
                print "| %sresponse content%s | (only first packet)" % (desc_color1, reset_color)
                print " " + "-" * 18
                print data['response_content']
            print
        elif view == 'batch':
            print ";;;;%s;;;;%s;;;;%s;;;;%s;;;;%s;;;;%s;;;;%0.5f;;;;%s;;;;%s" % (direction,
                                                                                 src, dst,
                                                                                 service,
                                                                                 data['request_time'],
                                                                                 data['response_time'],
                                                                                 duration,
                                                                                 data['request_content'],
                                                                                 data['response_content'])
        else:
            print bar_color + "/*" + "-" * 40 + "*/" + reset_color
            print
            if translate_ip:
                print "%s %s>%s %s (%s > %s)" % (src, desc_color1, reset_color, dst, host_src, host_dst)
            else:
                print "%s %s>%s %s" % (src, desc_color1, reset_color, dst)
            print "%sdirection%s            : %s" % (desc_color2, reset_color, direction)
            print "%sservice%s              : %s (%s)" % (desc_color2, reset_color, data['service'], data['protocol'])
            print "%sduration%s             : %ss" % (desc_color2, reset_color, data['duration'])
            if 'http_host' in data:
                if data['http_host']:
                    print "%shttp host%s            : %s" % (desc_color3, reset_color,
                                                             data['http_host'])
            if 'http_status_code' in data:
                if data['http_status_code']:
                    print "%shttp status code%s     : %s" % (desc_color3, reset_color,
                                                             data['http_status_code'])
            if 'http_varnish_caching' in data:
                if data['http_varnish_caching']:
                    print "%shttp varnish caching%s : %s" % (desc_color3, reset_color,
                                                             data['http_varnish_caching'])
            if 'mysql_method' in data:
                if data['mysql_method']:
                    print "%smysql method%s         : %s" % (desc_color3, reset_color,
                                                             data['mysql_method'])
            print "%srequest content%s (%s)" % (desc_color2, reset_color, data['request_time'])
            print data['request_content']
            if display_response_content:
                print "%sresponse content%s (%s) (only first packet)" % (desc_color2, reset_color, data['response_time'])
                print data['response_content']
            print


def final_process(signum, frame):
    """Display stats and exit."""

    if not ignore_process:
        # Processing last packet if exists
        if packet_info:
            if 'process_second' in packet_info:
                process()
        # Kill tcpdump
        proc.terminate()
        # Display
        display_full_stats()

    sys.exit(0)


def get_local_ip():
    """Get local ip of the current server."""

    if subprocess.call(['which', 'ip'], stdout=subprocess.PIPE) == 0:
        p = subprocess.Popen(['ip', 'addr'], stdout=subprocess.PIPE)
        ip = []
        for l in iter(p.stdout.readline, ''):
            m = re.search(r'inet (?P<ip>[\d\.]+)\/', l.rstrip())
            if m:
                ip.append(m.group('ip'))
    elif subprocess.call(['which', 'ifconfig'], stdout=subprocess.PIPE) == 0:
        p = subprocess.Popen('ifconfig', stdout=subprocess.PIPE)
        ip = []
        for l in iter(p.stdout.readline, ''):
            l = l.rstrip()
            m = re.search(r'inet (?:adr:)?(?P<ip>[\d\.]+)\s+', l)
            if m:
                ip.append(m.group('ip'))
    else:
        print >> sys.stderr, "\nERROR : 'ip' and 'ifconfig' command not found.\n"
        sys.exit(2)
    return ip


# MAIN
if __name__ == '__main__':

    # Get script name
    script_name = sys.argv[0]

    # Check if current user is 'root'
    if os.getuid() != 0:
        print >> sys.stderr, "\nERROR : only root can use this script.\n"
        sys.exit(2)

    # Check if 'tcpdump' command exists
    if not subprocess.call(['which', 'tcpdump'], stdout=subprocess.PIPE) == 0:
        print >> sys.stderr, "\nERROR : 'tcpdump' command not found.\n"
        sys.exit(2)

    # For services not in /etc/services
    # Syntax :
    # '<PROTOCOL><PORT>': '<SERVICE_NAME>'
    # Services http and http_* will be process differently in the statistics
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

    ###
    # Signals
    ###
    signal.signal(signal.SIGINT, final_process)
    signal.signal(signal.SIGALRM, final_process)
    signal.signal(signal.SIGTERM, final_process)
    signal.signal(signal.SIGHUP, final_process)

    ###
    # Initialization of data/timers/counters/caches/limits
    ###
    first_time = None
    last_time = None
    ignore_process = False
    packet_info = {}
    request_packets_info = {}
    response_packets_info = {}
    global_stats = {}
    extra_global_stats = {}
    matched_stats = {}
    extra_matched_stats = {}
    services_cache = {}
    services_cache['UDP'] = {}
    services_cache['TCP'] = {}
    dns_cache = {}
    dns_lookup_time_limit = 0.5
    packet_pass = False
    # buffer size for tcpdump command
    buffer_size = 4096
    # size of packet conserved
    snap_len = 2048

    ###
    # Default arguments
    ###
    input_pcap_file = None
    devices = None
    tcpdump_filter = None
    extra_filter = None
    ignore_case_match = False
    view = "normal"
    display_extra_global_stats = False
    display_extra_matched_stats = False
    by_line = False
    filter_match = False
    color = False
    translate_ip = False
    content_size = {}
    content_size['request'] = None
    content_size['response'] = None
    display_response_content = True
    apple_version = False
    display_extra_http_host_uri_level1 = False
    verbose = False
    debug = False

    extra_filter_regex = r'^(?P<negative>not )*(?:(?:(?P<std_field>\S+) \"(?P<std_regex>.+)\"$)|(?:(?P<greater_field>\S+) greater (?P<greater_min>[\d.]+)$|(?:(?P<less_field>\S+) less  (?P<less_max>[\d.]+)$)|(?:(?P<range_field>\S+) range (?P<range_min>[\d.]+)-(?P<range_max>[\d.]+)$)))'

    # Read arguments
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "d:F:E:iv:XlfctS:I:h",
                                   ["devices=", "tcpdump-filter=", "extra-filter=",
                                    "ignore-case-match", "view=", "extra",
                                    "extra-any", "extra-matched", "by-line,"
                                    "filter-match", "color", "translate-ip",
                                    "content-size=", "request-content-size=",
                                    "response-content-size=", "no-response-content",
                                    "apple-version", "extra-http-uri-level1",
                                    "input-pcap-file=", "verbose", "debug", "help"])
    except getopt.GetoptError as err:
        print >> sys.stderr, "\nERROR : %s\n" % err
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-d", "--devices"):
            devices = arg
        elif opt in ("-F", "--tcpdump-filter"):
            tcpdump_filter = arg
        elif opt in ("-E", "--extra-filter"):
            extra_filter_args = arg
            extra_filter = extra_filter_args.split(' and ')
            for i in extra_filter:
                if not re.match(extra_filter_regex, i):
                    print >> sys.stderr, "\nERROR : bad syntax for extra regex match\n"
                    sys.exit(2)
        elif opt in ("-i", "--ignore-case-match"):
            ignore_case_match = True
        elif opt in ("-v", "--view"):
            view = arg
        elif opt in ("-X", "--extra"):
            display_extra_global_stats = True
            display_extra_matched_stats = True
        elif opt == "--extra-any":
            display_extra_global_stats = True
        elif opt == "--extra-matched":
            display_extra_matched_stats = True
        elif opt in ("-l", "--by-line"):
            by_line = True
        elif opt in ("-f", "--filter-match"):
            filter_match = True
        elif opt in ("-c", "--color"):
            color = True
        elif opt in ("-t", "--translate-ip"):
            translate_ip = True
        elif opt in ("-S", "--content-size"):
            try:
                content_size['response'] = int(arg)
                content_size['request'] = int(arg)
            except ValueError:
                print >> sys.stderr, "\nERROR : bad type, '-S' or '--content-size' must be an integer\n"
                sys.exit(2)
        elif opt == "--request-content-size":
            try:
                content_size['request'] = int(arg)
            except ValueError:
                print >> sys.stderr, "\nERROR : bad type, '--request-content-size' must be an integer\n"
                sys.exit(2)
        elif opt == "--response-content-size":
            try:
                content_size['response'] = int(arg)
            except ValueError:
                print >> sys.stderr, "\nERROR : bad type, '--response-content-size' must be an integer\n"
                sys.exit(2)
        elif opt == "--no-response-content":
            display_response_content = False
        elif opt == "--apple-version":
            apple_version = True
        elif opt == "--extra-http-uri-level1":
            display_extra_http_host_uri_level1 = True
        elif opt in ("-I", "--input-pcap-file"):
            input_pcap_file = arg
            if input_pcap_file is not '-':
                if not os.path.isfile(input_pcap_file):
                    print >> sys.stderr, "\nERROR : input file '%s' does not exist\n" % input_pcap_file
                    sys.exit(2)
        elif opt == "--verbose":
            verbose = True
        elif opt == "--debug":
            debug = True
        elif opt in ("-h", "--help"):
            usage()

    if filter_match and not extra_filter:
        print >> sys.stderr, "\nERROR : missing matching arguments for -f (--filter-match)\n"
        sys.exit(2)

    # Get local ip
    local_ip = get_local_ip()

    # Logger init
    if debug:
        loglevel = logging.DEBUG
    elif verbose:
        loglevel = logging.INFO
    else:
        loglevel = logging.ERROR
    logger = logging.getLogger()
    logger.setLevel(loglevel)
    formatter = logging.Formatter('>>> %(levelname)8s - %(message)s')
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Variables for display identation
    stats_title_length = 37
    stats_level1_length = 2
    stats_level2_length = 4
    stats_level3_length = 6
    stats_level4_length = 8
    stats_level5_length = 10

    # Variables for string colorization
    # http://misc.flogisoft.com/bash/tip_colors_and_formatting
    red_bold = '\x1b[1;31m'
    red_bold_underlined = '\x1b[1;4;31m'
    red_background = '\x1b[41m'
    green_background = '\x1b[42m'
    green_bold_underlined = '\x1b[1;4;32m'
    blue_background = '\x1b[44m'
    grey_bold_background = '\x1b[1;100m'
    if color:
        matching_color = blue_background
        not_matching_color = red_background
        bar_color = grey_bold_background
        desc_color1 = red_bold
        desc_color2 = red_bold_underlined
        desc_color3 = green_bold_underlined
        reset_color = '\x1b[0m'
    else:
        matching_color = ''
        bar_color = ''
        desc_color1 = ''
        desc_color2 = ''
        desc_color3 = ''
        reset_color = ''

    # Header for 'batch' view
    if view == 'batch':
        print ";;;;direction;;;;src;;;;dst;;;;service;;;;first_time;;;;end_time;;;;duration;;;;request_content;;;;response_content"

    # Build arguments for tcpdump command
    tcpdump_command = ['tcpdump', '-vSelNnttttAUKl', '-B', str(buffer_size), '-s', str(snap_len)]
    tcpdump_extra_args = []
    if devices:
        tcpdump_extra_args += ['-i', devices]
    if tcpdump_filter:
        for i in tcpdump_filter.split():
            tcpdump_extra_args.append(i)
    if input_pcap_file:
        tcpdump_command += ['-r', input_pcap_file]

    # Launch tcpdump command
    proc = subprocess.Popen(tcpdump_command + tcpdump_extra_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            bufsize=-1)

    # Reading tcpdump output line by line
    for line in iter(proc.stdout.readline, ''):
        if not ignore_process:

            # Pass notification line of tcpdump
            if re.search(r'^(reading from file |tcpdump: |listening on )', line):
                continue

            # Cleaning line
            line = line.replace('\r', ' ')
            line = line.replace('\t', ' ')
            line = line.replace('\n', ' ')

            # First line
            # TCP example :
            # 2014-11-16 18:25:29.107844 c8:4c:75:f5:79:7f > c8:0a:a9:03:23:6c, ethertype IPv4 (0x0800), length 66: (tos 0x0, ttl 55, id 50657, offset 0, flags [DF], proto TCP (6), length 52)
            # or
            # 15:01:22.119548  In 06:c9:cc:00:03:74 (oui Unknown) ethertype IPv4 (0x0800), length 79: (tos 0x8, ttl 64, id 27035, offset 0, flags [DF], proto TCP (6), length 63)
            # UDP example :
            # 2014-11-16 18:30:34.737548 c8:0a:a9:03:23:6c > c8:4c:75:f5:79:7f, ethertype IPv4 (0x0800), length 69: (tos 0x0, ttl 64, id 14035, offset 0, flags [none], proto UDP (17), length 55)
            regex = r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{6})\s*(?P<direction>In|Out|)\s*(?P<localhost>[0:]{17}|).* ethertype (?P<ethertype>\S+) .* length (?P<length>\d+): (?P<remain>.*)"
            m = re.search(regex, line)
            if m:
                packet_pass = False
                if packet_info:
                    if 'process_second' in packet_info:
                        process()
                        packet_info = {}
                if m.group('localhost'):
                    packet_info['direction'] = 'LOCAL'
                elif m.group('direction') == 'In':
                    packet_info['direction'] = 'INPUT'
                elif m.group('direction') == 'Out':
                    packet_info['direction'] = 'OUTPUT'
                packet_info['time'] = m.group('time')
                packet_info['ethertype'] = m.group('ethertype')
                packet_info['length_ip'] = int(m.group('length'))
                if packet_info['ethertype'] != 'IPv4':
                    logging.debug('### ETHERTYPE NOT SUPPORTED : %s ###', packet_info)
                    packet_pass = True
                    packet_info = {}
                    continue
                regex = r"proto (?P<protocol>\S+).*length (?P<length>\d+)"
                n = re.search(regex, m.group('remain'))
                if n:
                    packet_info['protocol'] = n.group('protocol')
                    packet_info['length_tcp'] = int(n.group('length'))
                    if packet_info['protocol'] not in ['TCP', 'UDP']:
                        logging.debug('### PROTOCOL NOT SUPPORTED : %s ###', packet_info)
                        packet_pass = True
                        packet_info = {}
                        continue
                continue
            elif packet_pass:
                continue

            # Second line
            # example :
            # TCP example :
            #     98.122.152.153.60554 > 125.152.111.111.22: Flags [.], cksum 0xb653 (correct), ack 143092973, win 5448, options [nop,nop,TS val 202331192 ecr 3438189682], length 0
            # UDP example :
            #     125.152.111.111.52547 > 88.191.254.60.53: 38670+ A? google.fr. (27)
            regex = r"^\s*(?P<ip_src>\d+.\d+.\d+.\d+).(?P<port_src>\d+) > (?P<ip_dst>\d+.\d+.\d+.\d+).(?P<port_dst>\d+): (?:Flags \[(?P<flags>\S+)\].* length (?P<length>\d+)|(?P<content>.*))"
            m = re.search(regex, line)
            if m:
                if packet_info:
                    packet_info['ip_src'] = m.group('ip_src')
                    packet_info['port_src'] = int(m.group('port_src'))
                    packet_info['ip_dst'] = m.group('ip_dst')
                    packet_info['port_dst'] = int(m.group('port_dst'))
                    packet_info['content'] = ''
                    if packet_info['protocol'] == 'TCP':
                        if m.group('flags'):
                            packet_info['flags'] = m.group('flags')
                        if m.group('length'):
                            packet_info['length_data'] = int(m.group('length'))
                    elif packet_info['protocol'] == 'UDP':
                        if m.group('content'):
                            packet_info['content'] = 'decoded >>>\n %s\ncoded >>>\n ' % m.group('content')
                    packet_info['process_second'] = True
                    continue
                else:
                    logging.error('### PACKET IS INCOMPLETE OR NOT A CLASSIC UDP/TCP PACKET : %s (%s) ###',
                                  packet_info, line)
                    continue

            # Packet not supported
            if re.search(r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{6}) .*", line):
                logging.info('### PACKET IS NOT SUPPORTED : (%s) ###', line)
                if packet_info:
                    if 'process_second' in packet_info:
                        process()
                        packet_info = {}
                continue

            # Data line
            if 'content' in packet_info:
                packet_info['content'] += "%s\n" % line

    # Finish capture
    final_process(None, None)
