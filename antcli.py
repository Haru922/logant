import configparser
import argparse
import datetime
import sqlite3

LOGANT_CONF = '/home/haru/logant.conf'

def get_log(c, syslog_identifier, log_start_time, log_end_time, verbose):
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

    for d in c:
        if verbose:
            print(' '.join([str(d[i]) for i in d.keys()]))
        else:
            print(d['__REALTIME_TIMESTAMP'], d['PRIORITY'], d['MESSAGE'], d['GRMCODE'], d['SYSLOG_IDENTIFIER'])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--id', type=str, help='syslog identifier.', default='')
    parser.add_argument('-s', '--start', type=str, help='log start time.', default='1')
    parser.add_argument('-e', '--end', type=str, help='log end time.', default=str(datetime.datetime.now()))
    parser.add_argument('-v', '--verbose', help='display all columns.', action='store_true')
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(LOGANT_CONF)

    database = config['LOGANT']['GSL_DATABASE']
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    get_log(c, args.id, args.start, args.end, args.verbose)

    conn.close()
