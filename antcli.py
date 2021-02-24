#!/usr/bin/python3

import configparser
import argparse
import datetime
import sqlite3

LOGANT_CONF = '/usr/lib/gooroom-security-utils/logant.conf'

def get_log(c, syslog_identifier, log_start_time, log_end_time, details, verbose):
    cnt = 0
    if syslog_identifier:
        query = ''' SELECT *
                    FROM GOOROOM_SECURITY_LOG
                    WHERE SYSLOG_IDENTIFIER == ?
                    AND __REALTIME_TIMESTAMP BETWEEN ? AND ?
                    ORDER BY __REALTIME_TIMESTAMP '''
        c.execute(query, (syslog_identifier, log_start_time, log_end_time,))
    else:
        query = ''' SELECT *
                    FROM GOOROOM_SECURITY_LOG
                    WHERE __REALTIME_TIMESTAMP BETWEEN ? AND ?
                    ORDER BY __REALTIME_TIMESTAMP '''
        c.execute(query, (log_start_time, log_end_time,))

    keys = ''
    for row in c:
        cnt += 1
        if not keys:
            keys = row.keys() if details else ['__REALTIME_TIMESTAMP', 'PRIORITY', 'MESSAGE', 'GRMCODE', 'SYSLOG_IDENTIFIER']
        if verbose:
            for key in keys:
                print('{}: {}'.format(key, row[key]))
            print()
        else:
            print(' | '.join([str(row[key]) for key in keys]))
    print('log count: {}'.format(cnt))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--id', type=str, help='syslog identifier.', default='')
    parser.add_argument('-s', '--start', type=str, help="log start time. (FORMAT: 'Year-Month-Day Hour:Minutes:Seconds')", default='1')
    parser.add_argument('-e', '--end', type=str, help="log end time. (FORMAT: 'Year-Month-Day Hour:Minutes:Seconds')", default=str(datetime.datetime.now()))
    parser.add_argument('-d', '--details', help='display details.', action='store_true')
    parser.add_argument('-v', '--verbose', help='display with column names.', action='store_true')
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(LOGANT_CONF)

    database = config['LOGANT']['GSL_DATABASE']
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    get_log(c, args.id, args.start, args.end, args.details, args.verbose)

    conn.close()
