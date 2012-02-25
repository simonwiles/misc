#!/usr/bin/env python
#-*- coding:utf-8 -*-

"""

    HTTPD log sumarizer, based in part on the http scripts from `logwatch',
    but intended to work better with multiple virtual hosts.

    vhosts_logwatch.py --host=example.org [--date=2011-01-01[..2011-01-31]]

    * Automatically locates both Nginx and Apache2 vhosts (because part of the
       rationale for making this is aggregation of logs for sites running on
       Apache2 behind an Nginx reverse-proxy).

    * Automatically detects Apache2 logformat, and parses log lines accordingly


    TODO:
    * nginx logformat autodiscovery (currently hard-coded to the default value)
    * non-extension detected filetypes
    * non-standard timestamps ( %{format}t )
    * some kind of identification of exploit attempts?

"""

__program_name__ = 'logwatch.py'
__version__ = '0.2'
__author__ = 'Simon Wiles'
__email__ = 'simonjwiles@gmail.com'
__copyright__ = 'Copyright (c) 2011, Simon Wiles'
__license__ = 'GPL http://www.gnu.org/licenses/gpl.txt'
__date__ = '2011'


import sys
import os
import re
import gzip
import logging
import urllib
from datetime import date, datetime, timedelta
from time import mktime
from glob import glob
from itertools import chain
from operator import itemgetter

FILETYPES = {
    'image': ('Images', (
        '.bmp', '.cdr', '.emz', '.gif', '.ico', '.jpeg', '.jpg', '.png',
        '.svg', '.sxd', '.tif', '.tiff', '.wbmp', '.wmf', '.wmz', '.xdm',
    ), ()),
    'content': ('Content Pages', (
       '.htm', '.html', '.jhtml', '.phtml', '.shtml',
       '.inc', '.php', '.php3', '.asmx', '.asp', '.pl', '.wml',
       '.torrent',
       '.css', '.js', '.cgi',
       '.fla', '.swf', '.rdf',
       '.class', '.jsp', '.jar', '.java', '.txt',
    ), ('server-status', 'server-info', 'announce', 'scrape',
        'COPYRIGHT', 'README', 'FAQ', 'INSTALL',
    )),
    'docs': ('Documents', (
        '.asc', '.bib', '.djvu', '.doc', '.dot', '.dtd', '.dvi', '.gnumeric',
        '.mcd', '.mso', '.pdf', '.pps', '.ppt', '.ps', '.rtf', '.sxi', '.tex',
        '.text', '.tm', '.xls', '.xml', '.odt', '.ods', '.odp'
    ), ()),
    'archive': ('Archives', (
        '.ace', '.bz2', '.cab', '.deb', '.dsc', '.ed2k', '.gz', '.hqx', '.md5',
        '.rar', '.rpm', '.sig', '.sign', '.tar', '.tbz2', '.tgz', '.vl2', '.z',
        '.zip',
    ), ()),
    'audio': ('Audio Files', (
        '.au', '.aud', '.mid', '.mp3', '.ogg', '.pls', '.ram', '.raw', '.rm',
        '.wav', '.wma', '.wmv', '.xsm',
    ), ()),
    'video': ('Video Files', (
        '.asf', '.ass', '.avi', '.idx', '.mid', '.mpg', '.mpeg', '.mov', '.qt',
        '.psb', '.srt', '.ssa', '.smi', '.sub',
    ), ()),
    'winexec': ('Windows Executables', ('.bat', '.com', '.exe', '.dll'), ()),
    'wpad': ('Web-Proxy Autodiscovery', (), (
       'wpad.dat', 'wspad.dat', 'proxy.pac'
    )),
    'sourcecode': ('Program Sourcecode', (
        '.bas', '.c', '.cpp', '.diff', '.f', '.h', '.init', '.m', '.mo',
        '.pas', '.patch', '.po', '.pot', '.py', '.sh', '.spec',
    ), ()),
    'diskimage': ('Disk Images', ('.bin', '.cue', '.img', '.iso', '.run'), ()),
    'log': ('Log files', ('.log', '.logs', '.out', '.wyniki'), ()),
    'fonts': ('Font Files', ('.atf', '.ttf'), ()),
    'config': ('Config Files', (
        '.cfg', '.conf', '.config', '.ini', '.properties'
    ), ()),
    'mozext': ('Mozilla Extensions', ('.xpt', '.xul'), ()),
    'other': ('Other (unknown)', (), ()),
    'redirect': ('Redirection', (), ()),
    'proxy': ('Proxy Requests', (), ()),
}

STATUS_CODES = {
    100: 'Continue',
    101: 'Switching Protocols',
    102: 'Processing',                      # WebDAV
    200: 'OK',
    201: 'Created',
    202: 'Accepted',
    203: 'Non-Authoritative Information',
    204: 'No Content',
    205: 'Reset Content',
    206: 'Partial Content',
    207: 'Multi-Status',                    # WebDAV
    300: 'Multiple Choices',
    301: 'Moved Permanently',
    302: 'Found',
    303: 'See Other',
    304: 'Not Modified',
    305: 'Use Proxy',
    307: 'Temporary Redirect',
    400: 'Bad Request',
    401: 'Unauthorized',
    402: 'Payment Required',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    406: 'Not Acceptable',
    407: 'Proxy Authentication Required',
    408: 'Request Timeout',
    409: 'Conflict',
    410: 'Gone',
    411: 'Length Required',
    412: 'Precondition Failed',
    413: 'Request Entity Too Large',
    414: 'Request-URI Too Large',
    415: 'Unsupported Media Type',
    416: 'Request Range Not Satisfiable',
    417: 'Expectation Failed',
    422: 'Unprocessable Entity',            # WebDAV
    423: 'Locked',                          # WebDAV
    424: 'Failed Dependency',               # WebDAV
    499: 'Client Closed Request (Nginx)',
    500: 'Internal Server Error',
    501: 'Not Implemented',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
    505: 'HTTP Version Not Supported',
    507: 'Insufficient Storage',            # WebDAV
}

STATUS_CODE_GROUPS = {
    '1xx':  'Informational',
    '2xx':  'Successful',
    '3xx':  'Redirection',
    '4xx':  'Client Error',
    '5xx':  'Server Error',
}

FORMAT_MAP_APACHE2 = {
    '%h':   ('([\d.]+)', 'client_ip'),
    '%H':   ('(\S*?)', 'request_protocol'),
    '%m':   ('([A-Z]+)', 'method'),
    '%l':   ('(\\S*?)', 'ident'),
    '%u':   ('(\\S*?)', 'userid'),
    '%t':   ('(\[[^\]]+\])', 'timestamp'),
    '%r':   ('(.*)', 'request'),
    '%s':   ('(\\d{3})', 'http_rc'),
    '%>s':  ('(\\d{3})', 'http_rc'),
    '%b':   ('(-|\\d*)', 'bytes_transferred'),
    '%U':   ("((?:[A-Za-z0-9\-._~!$&'()*+,;=:@/]|%[A-Za-z0-9])+)", 'url_path'),
    '%q':   ('(\?\S+)?', 'query_string'),
    '%{Referer}i':   ('(.*)', 'referrer'),
    '%{User-Agent}i':   ('(.*)', 'agent'),
    '%{Host}i':   ('([\w.]+)', 'host'),
    '%O':   ('(\d+)', 'bytes_sent'),
    '[^%]+': None,
}

FORMAT_MAP_NGINX = {
    r'$remote_addr':   ('([\d.]+)', 'client_ip'),
    r'$remote_user':   ('(\\S+?)', 'userid'),
    r'$time_local':   ('(\S+ [+\-]\d{4})', 'timestamp'),
    r'$request':   ('(.*)', 'request'),
    r'$status':   ('(\\d{3})', 'http_rc'),
    # note: $body_bytes_sent maps to bytes_transferred
    r'$body_bytes_sent':   ('(-|\\d*)', 'bytes_transferred'),
    r'$http_referer':   ('(.*)', 'referrer'),
    r'$http_user_agent':   ('(.*)', 'agent'),
    r'$bytes_sent':   ('(\d+)', 'bytes_sent'),
    r'[^\$]+': None,
}

RE_ESCAPE = re.compile(r'([\[\]\(\)])')


def prep_logging(verbose=0, quiet=False):
    """ Configures a logging instance. """
    log_level = logging.CRITICAL if quiet else \
        (logging.WARNING, logging.INFO, logging.DEBUG)[verbose]
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s.%(msecs)03d: %(levelname)s: %(message)s',
        datefmt='%H:%M:%S',
    )


def format_bytes(num_bytes):
    """ Returns a human-readable number in binary-prefixed units.

        Binary-prefixed units are KiB, MiB (powers of 1024) and so on.
        Decimal-prefixed units are KB, MB (powers of 1000) etc.

        Note: will fail with numbers greater than 1024TiB :)
    """
    scaled = num_bytes
    for unit in ('bytes', 'KiB', 'MiB', 'GiB', 'TiB'):
        if scaled < 1024.0:
            return "{0:.1f} {1}".format(scaled, unit)
        scaled /= 1024.0
    raise ValueError('number too large')


def daterange(start, stop, step_days=1):
    """ Generator to yield date objects """
    current = start
    step = timedelta(step_days)
    if step_days > 0:
        while current <= stop:
            yield current
            current += step
    elif step_days < 0:
        while current >= stop:
            yield current
            current += step
    else:
        raise ValueError("daterange() step_days argument must not be zero")


class LogSumarizer():
    """ DOCSTRING """

    def __init__(self, host=None, period=None, config_base='/etc'):

        self.host = host
        self.period = period
        self.apache_config_base = os.path.join(config_base, 'apache2')
        self.nginx_config_base = os.path.join(config_base, 'nginx')

        self.decode_urls = True

        report_period = self.period \
                     if isinstance(period, basestring) else ' to '.join(period)

        self.report = {
            'host': self.host,
            'period': report_period,
        }

        self.prepare_report()

    def prepare_report(self):

        apache2_vhost_config = self.get_vhost_config_apache2(self.host)
        nginx_vhost_config = self.get_vhost_config_nginx(self.host)

        if apache2_vhost_config is None and nginx_vhost_config is None:
            logging.fatal(
                'Host "{0}" could not be found!  Aborting!'.format(self.host))
            raise SystemExit

        if apache2_vhost_config is not None:
            logfile_base, logformat = \
                                 self.parse_vhost_apache2(apache2_vhost_config)
            parser_regex, tokens = self.set_parser_regex_apache2(logformat)
            loglines = self.gather_data(logfile_base, logformat)
            self.report['apache2'] = \
                               self.process_log(loglines, parser_regex, tokens)

        if nginx_vhost_config is not None:
            logfile_base, logformat = \
                                     self.parse_vhost_nginx(nginx_vhost_config)
            parser_regex, tokens = self.set_parser_regex_nginx(logformat)
            loglines = self.gather_data(logfile_base, logformat)
            self.report['nginx'] = \
                               self.process_log(loglines, parser_regex, tokens)

    def set_parser_regex_apache2(self, logformat):
        """ build a regex to parse log lines, and return it along with an
            ordered list of tokens which corresponds to the order of matching
            groups in the regex.
        """

        def format_mapper(scanner, token):
            """ map tokens to their information """
            return FORMAT_MAP_APACHE2.get(
                                     token, ('({0})'.format(token), 'unknown'))

        scanner = re.Scanner([('|'.join(FORMAT_MAP_APACHE2), format_mapper)])

        tokens, remainder = scanner.scan(logformat)

        if remainder.strip() != '':
            logging.fatal('error parsing logformat:\n\t\t{0}\n\tunparsed!'\
                                                            .format(remainder))
            raise SystemExit

        parser_regex = re.compile(''.join(t[0] for t in tokens))

        return parser_regex, tokens

    def set_parser_regex_nginx(self, logformat):
        """ build a regex to parse log lines, and return it along with an
            ordered list of tokens which corresponds to the order of matching
            groups in the regex.
        """

        def format_mapper(scanner, token):
            """ map tokens to their information """
            return FORMAT_MAP_NGINX.get(
             token, ('({0})'.format(RE_ESCAPE.sub(r'\\\1', token)), 'unknown'))

        scanner = re.Scanner([('|'.join(a.replace('$', '\$') \
                                   for a in FORMAT_MAP_NGINX), format_mapper)])

        tokens, remainder = scanner.scan(logformat)

        if remainder.strip() != '':
            logging.fatal('error parsing logformat:\n\t\t{0}\n\tunparsed!'\
                                                            .format(remainder))
            raise SystemExit

        parser_regex = re.compile(''.join(t[0] for t in tokens))

        return parser_regex, tokens

    def parse_vhost_apache2(self, vhost_config):

        customlog_regex = re.compile(r'\bCustomLog\s+(\S*)\s+(.*?)\n')

        customlog = customlog_regex.findall(vhost_config)
        if len(customlog) != 1:
            logging.fatal("Can't identify unique 'CustomLog' line"
                            " in vhost config.  Aborting!")
            raise SystemExit

        logfile_base, logformat = customlog[-1]

        if len(logformat) - len(logformat.strip('"')) == 2:
            # logformat is inline (not 'nicknamed')
            return logfile_base, logformat
        else:
            # logformat is 'nicknamed'
            logformat = \
                self.get_apache_logformat_by_nickname(logformat, vhost_config)

            if logformat:
                return logfile_base, logformat

            logging.fatal(
                  "Can't identify logformat {0}.  Aborting!".format(logformat))
            raise SystemExit

    def parse_vhost_nginx(self, vhost_config):

        accesslog_regex = re.compile(r'\baccess_log\s+[^;]+;')

        accesslogs = accesslog_regex.findall(vhost_config)
        for accesslog in accesslogs[::-1]:
            if accesslog.split()[1] == 'off;':
                del accesslogs[accesslogs.index(accesslog)]
        if len(accesslogs) < 1:
            logging.fatal("Unable to find an 'access_log' line"
                            " in server_block.  Not able to handle this yet!")
            raise SystemExit
        if len(accesslogs) > 1:
            logging.fatal("Found multiple 'access_log' lines"
                            " in server_block.  Not able to handle this yet!")
            raise SystemExit

        accesslog = accesslogs[0].split()
        logfile_base = accesslog[1].strip(';')
        if len(accesslog) > 2:
            logging.warning('found an Nginx logformat, but don\'t know what to'
                                              ' do with these yet!  Ignoring!')
            logformat = accesslog[2]

        logformat = ('$remote_addr - $remote_user [$time_local] "$request" '\
                 '$status $body_bytes_sent "$http_referer" "$http_user_agent"')

        return logfile_base, logformat

    def get_apache_logformat_by_nickname(self, nickname, vhost_config=None):
        """ Finds the logformat string which corresponds to a given nickname.
            Checks a specified vhost config first, if specified, since this
            takes precedence.  Always returns the last entry found.
        """

        logformat_regex = \
            re.compile(r'\bLogFormat\s+"(.*)"\s+{0}\n'.format(nickname))

        if vhost_config:
            try:
                return logformat_regex.findall(vhost_config)[-1]
            except IndexError:
                pass

        for config_file in ('apache2.conf', 'httpd.conf'):
            conf_path = os.path.join(self.apache_config_base, config_file)
            with open(conf_path) as conf:
                try:
                    return logformat_regex.findall(conf.read())[-1]
                except IndexError:
                    pass

        return False

    def get_vhost_config_apache2(self, host):
        vhost_regex = re.compile(
                    r'\s*<VirtualHost[^>]*>\s*(.*?)\s*</VirtualHost>\s*', re.S)
        host_regex = re.compile(r'\bServerName\s+{0}\b'.format(host))

        glob_pattern = os.path.join(
                                 self.apache_config_base, 'sites-enabled', '*')

        try:
            for vhost_file in glob(glob_pattern):
                with open(vhost_file) as file_handle:
                    file_contents = file_handle.read()
                    for vhost_config in vhost_regex.findall(file_contents):
                        if host_regex.search(vhost_config):
                            return vhost_config
        except IOError as err:
            logging.fatal(err)
            raise SystemExit

        return None

    def get_vhost_config_nginx(self, host):
        """ returns the first server block found under the nginx config
            path which contains "server_name <host>;"
        """

        host_regex = re.compile(r'\bserver_name\s+{0}\s*;'.format(host))

        glob_pattern = os.path.join(
                                 self.nginx_config_base, 'sites-enabled', '*')

        def get_server_blocks(config):
            return re.split(ur'\b(server\s+{)', config)

        try:
            for vhost_file in glob(glob_pattern):
                with open(vhost_file) as file_handle:
                    file_contents = file_handle.read()
                    for server_block in get_server_blocks(file_contents):
                        if host_regex.search(server_block):
                            return server_block
        except IOError as err:
            logging.fatal(err)
            raise SystemExit

        return None

    def gather_data(self, logfile_base, logformat):

        logging.debug('logfile_base = {0}'.format(logfile_base))
        logging.debug('logformat = "{0}"'.format(logformat))

        if not os.access(logfile_base, os.R_OK):
            logging.fatal('Permission denied accessing "{0}", aborting!'\
                                                         .format(logfile_base))
            raise SystemExit

        if isinstance(self.period, basestring):
            date_object = datetime.strptime(self.period, '%Y-%m-%d')
            date_regex = re.compile(date_object.strftime('%d/%b/%Y'))
            earliest_date = mktime(date_object.timetuple())
        else:
            date_objects = \
              [datetime.strptime(period, '%Y-%m-%d') for period in self.period]
            date_regexes = \
                    [re.compile(date_object.strftime('%d/%b/%Y')) for \
                        date_object in daterange(*date_objects)]
            earliest_date = mktime(min(date_objects).timetuple())

        logfiles = [fname for fname in glob('{0}*'.format(logfile_base)) \
            if os.path.getmtime(fname) >= earliest_date]

        logging.debug(
                     'Logfiles to check:\n\t{0}'.format('\n\t'.join(logfiles)))

        if isinstance(self.period, basestring):
            loglines = list(chain(*[[line for line in self.get_lines(logf) \
                if date_regex.search(line) is not None] for logf in logfiles]))
        else:
            lines = list(chain(*[self.get_lines(logf) for logf in logfiles]))
            loglines = list(chain(*[[
                 line for line in lines if re_date.search(line) is not None] \
                                                 for re_date in date_regexes]))

        logging.debug('Total loglines to parse: {0}'.format(len(loglines)))

        return loglines

    def process_log(self, loglines, parser_regex, tokens):
        """ accept the list of log lines to be processed (or a generator
            yielding them), the regex to parse the lines with, and the list on
            tokens to interpret the matching groups, and return a dictionary of
            crunched statistics for building reports from.
        """
        lines_processed = 0
        total_bytes = 0
        by_status = {}
        by_ctype = {}
        errors = {}
        unparsed = []
        bytecounts_include_headers = False

        fields = [t[1] for t in tokens]

        if 'bytes_transferred' in fields:
            bytes_field = 'bytes_transferred'
        elif 'bytes_sent' in fields:
            bytecounts_include_headers = True
            bytes_field = 'bytes_sent'
        else:
            # we don't seem to have what we need!
            logging.fatal(
                "Logformat is missing either 'bytes_transferred' (%b), or "
                       "'bytes_sent' (%O, includes headers).  Cannot proceed!")
            raise SystemExit

        re_request = re.compile(r'(\S+) (.*) (\S+)')

        for line in loglines:
            parsed = parser_regex.match(line.strip())

            if parsed is None:
                unparsed.append(line)
                continue

            lines_processed += 1
            hashed = dict(zip(fields, parsed.groups()))

            if 'request' in fields and hashed['http_rc'] == '400' \
                and (hashed['request'].strip(r'\x0-') == ''):
                # 400 error with '-' or a long string of null-bytes as the
                #  request -- the former seems to be a mod_wsgi issue (?) and
                #  the latter is probably a break-in attempt, I think...
                hashed['url'] = '-'
                hashed['url_path'] = '-'
                hashed['method'] = '-'
            elif 'request' in fields:
                # if using %r (request) instead of %q %U %m %H etc., we're
                #  gonna have to parse that here, too.
                #try:
                    #hashed['method'], hashed['url'], hashed['request_protocol'] = \
                        #hashed['request'].split(' ')
                #except:
                    #print hashed['request']
                    #raise SystemExit

                parsed_request = re_request.match(hashed['request'])
                hashed['method'], hashed['url'], hashed['request_protocol'] = \
                                                        parsed_request.groups()

                if hashed['url'].count('?'):
                    hashed['url_path'], hashed['query_string'] = \
                        hashed['url'].split('?', 1)
                else:
                    hashed['url_path'] = hashed['url']

            elif 'url_path' in fields and 'query_string' in fields:
                hashed['query_string'] = '' if hashed['query_string'] is None \
                                                else hashed['query_string']
                hashed['url'] = '{url_path}{query_string}'.format(**hashed)

            else:
                # we don't seem to have what we need!
                logging.fatal(
                "Logformat is missing either 'request' (%r), or 'url_path' "
                              "(%U) and 'query_string' (%q).  Cannot proceed!")
                raise SystemExit

            # if bytes_field is '-' or doesn't exist, set it to 0
            try:
                rbytes = int(hashed.get(bytes_field, 0))
            except ValueError:
                rbytes = 0

            hashed['http_rc'] = int(hashed['http_rc'])

            total_bytes += rbytes

            def update_count(count_dict, key, rbytes):
                counter = count_dict.get(key, [0, 0])
                counter[0] += 1
                counter[1] += rbytes
                count_dict[key] = counter

            ##### Log Status Code ##
            if hashed['http_rc'] >= 500:
                update_count(by_status, '5xx', rbytes)
            elif hashed['http_rc'] >= 400:
                update_count(by_status, '4xx', rbytes)
            elif hashed['http_rc'] >= 300:
                update_count(by_status, '3xx', rbytes)
            elif hashed['http_rc'] >= 200:
                update_count(by_status, '2xx', rbytes)
            else:
                update_count(by_status, '1xx', rbytes)

            ####  Count types and bytes ######
            filename = os.path.basename(hashed['url_path']).lower()
            extension = os.path.splitext(hashed['url_path'])[1].lower()
            matched = False
            for filetype in FILETYPES:
                if extension in FILETYPES[filetype][1]:
                    update_count(by_ctype, filetype, rbytes)
                    matched = True
                    break

                if filename in FILETYPES[filetype][2]:
                    update_count(by_ctype, filetype, rbytes)
                    matched = True
                    break

            if not matched:
                if hashed['url_path'][-1] == '/':
                    update_count(by_ctype, 'content', rbytes)
                elif hashed['http_rc'] >= 300 and hashed['http_rc'] < 400:
                    update_count(by_ctype, 'redirect', rbytes)
                elif hashed['method'] == 'CONNECT':
                    update_count(by_ctype, 'proxy', rbytes)
                    #proxy_host[hashed['client_ip']+' -> '+hashed['base_url']]
                    #   += 1
                else:
                    update_count(by_ctype, 'other', rbytes)
            ##############

            ##### Log Error-code Response ##
            if hashed['http_rc'] >= 400:
                err_code = errors.get(hashed['http_rc'], {})
                err_code[hashed['url']] = err_code.get(hashed['url'], 0) + 1
                errors[hashed['http_rc']] = err_code

        ##### Sanity Checks ##
        assert lines_processed == sum([a[0] for a in by_ctype.values()]) == \
                    sum([a[0] for a in by_status.values()])
        assert total_bytes == sum([a[1] for a in by_ctype.values()]) == \
                    sum([a[1] for a in by_status.values()])

        return {
            'lines_processed': lines_processed,
            'total_bytes': total_bytes,
            'by_ctype': by_ctype,
            'by_status': by_status,
            'errors': errors,
            'unparsed': unparsed,
            'bytecounts_include_headers': bytecounts_include_headers,
        }

    def get_lines(self, logfile):
        """ return the lines from a log file, uncompressing first if necessary.
        """
        if os.path.splitext(logfile)[1].lower() == '.gz':
            return gzip.open(logfile).readlines()
        else:
            return open(logfile).readlines()

    def print_report(self, output=sys.stdout):
        """ print a report to 'output' (a file-like object, defaults to STDOUT)
        """

        def write_line(data_line=''):
            """ write a line to 'output' """
            output.write(str(data_line) + '\n')

        header = '== Report for {host}, {period} ===='.format(**self.report)
        write_line('=' * len(header))
        write_line(header)
        write_line('=' * len(header))

        if 'apache2' in self.report:
            write_line()
            write_line('==== APACHE2 ====')
            write_line()
            self.write_table(self.report['apache2'], write_line)
            write_line()

        if 'nginx' in self.report:
            write_line()
            write_line('==== NGINX ====')
            write_line()
            self.write_table(self.report['nginx'], write_line)
            write_line()

    def write_table(self, data, write_line):

        pat = ' {0:30}{1:>20}{2:>20}'

        # write table header
        write_line(pat.format(
                           'Request Breakdown', 'No. Requests', 'Total Bytes'))
        if data['bytecounts_include_headers']:
            write_line('{0:>71}'.format('(includes headers)'))
        else:
            write_line('{0:>71}'.format('(excludes headers)'))
        write_line('-' * 72)
        write_line(pat.format('Total',
                   data['lines_processed'], format_bytes(data['total_bytes'])))
        write_line('-' * 72)

        # write table of responses by http response status
        write_line()
        write_line('- By Status Code {0}'.format('-' * 55))
        for status in ('1xx', '2xx', '3xx', '4xx', '5xx'):
            counter = data['by_status'].get(status, (0, 0))
            write_line(pat.format(
                '  {0} ({1}):'.format(status, STATUS_CODE_GROUPS[status]),
                counter[0], format_bytes(counter[1])))

        # write table of responses by content type
        write_line()
        write_line('- By Content Type {0}'.format('-' * 54))
        for ctype in sorted(data['by_ctype'], key=itemgetter(1), reverse=True):
            counter = data['by_ctype'][ctype]
            write_line(pat.format('  {0}:'.format(FILETYPES[ctype][0]),
                    counter[0], format_bytes(counter[1])))

        write_line()
        write_line()

        write_line('Requests with Error Response Codes:')
        write_line('-----------------------------------')
        for error_code in sorted(data['errors']):
            write_line(
                   '  {0} ({1}):'.format(error_code, STATUS_CODES[error_code]))
            requests = sorted(data['errors'][error_code].iteritems(), \
                                       key=lambda (k, v): (v, k), reverse=True)
            for request in requests:
                times = request[1]
                url = request[0]
                if self.decode_urls:
                    url = urllib.unquote(url)
                write_line('    {0:>2} time(s): {1}'.format(times, url))


def main():
    """ Command-line operation """

    import optparse

    optparser = optparse.OptionParser()
    optparser.add_option('-v', '--verbose', action='count', default=0,
                    help='Increase verbosity (specify twice for full debug)')
    optparser.add_option('-q', '--quiet', dest='quiet', action='store_true',
                        default=False, help="quiet operation")

    optparser.add_option('--date', dest='period', action='store',
        default=None, help="date (or date range) to compile logs for (must be "
         "in the format YYYY-MM-DD, and defaults to yesterday)\nCan be a date "
                            "range specified as, e.g., 2010-01-01..2010-01-31")

    optparser.add_option('--host', dest='host', action='store',
                         default=None, help="host to search for")

    optparser.add_option('--config-base', dest='config_base', action='store',
                         default='/etc',
       help='location to look for apache config files (default: /etc)')

    opts, args = optparser.parse_args()
    prep_logging(opts.verbose, opts.quiet)

    period = opts.period or (date.today() - timedelta(1)).strftime('%Y-%m-%d')

    if '..' in period:
        period = period.split('..')

    if opts.host is None:
        logging.fatal('No host specified (can\'t handle this yet!) - Aborting')
        raise SystemExit

    if opts.host == 'default':
        opts.host = '_'

    log = LogSumarizer(host=opts.host, period=period, config_base=opts.config_base)

    log.print_report()


if __name__ == '__main__':
    main()
