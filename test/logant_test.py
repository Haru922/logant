import configparser
import time
import enum
import sys

from systemd import journal

class JournalLevel(enum.Enum):
    none = -1
    emerg = 0
    alert = 1
    crit = 2
    err = 3
    warning = 4
    notice = 5
    info = 6
    debug = 7

transmit = { 'gbp-daemon': 'info',
             'gop-daemon': 'info',
             'gep-daemon': 'info',
             'GRAC': 'info',
             'gooroom-browser': 'info',
             'gooroom-agent': 'none' }

notify = { 'gbp-daemon': 'err',
           'gop-daemon': 'err',
           'gep-daemon': 'notice',
           'GRAC': 'err',
           'gooroom-browser': 'err',
           'gooroom-agent': 'info' }

show = { 'gbp-daemon': 'info',
         'gop-daemon': 'info',
         'gep-daemon': 'info',
         'GRAC': 'info',
         'gooroom-browser': 'info',
         'gooroom-agent': 'info' }

if __name__=='__main__':
    config = configparser.ConfigParser()
    config.read('logant_test.conf')
    sections = config.sections()

    N = 0
    M = 0
    cnt = {}
    for section in sections:
        cnt[section] = 0;
        for grmcode, message in config[section].items():
            flag = grmcode[0]
            grmcode = grmcode[2:]
            priority = 'info' if flag == 'n' else 'err'
            if flag == 'n':
                N += 1
            else:
                M += 1
            priority = JournalLevel[priority].value
            journal.sendv('MESSAGE='+message, 'SYSLOG_IDENTIFIER='+section, 'PRIORITY='+str(priority), 'GRMCODE='+grmcode)
            cnt[section] += 1;
    print('normal: {}, error: {}'.format(N, M))
