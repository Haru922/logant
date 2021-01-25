import re
import sys
import time
import sqlite3
import datetime
import importlib

from systemd import journal
from gsl_util import load_log_config,syslog_identifier_map

g_gop_regex = re.compile('GRMCODE=\w+')
GRAC_NETWORK_NAME = 'GRAC: Disallowd Network'
P_CAUSE = re.compile('cause=\S*')
P_FILE = re.compile('name=\S*')

class LogAnt:
    feature = { '__REALTIME_TIMESTAMP': 0,
                'PRIORITY': 1,
                'MESSAGE': 2,
                'GRMCODE': 3,
                'SYSLOG_IDENTIFIER': 4,
                '_TRANSPORT': 5,
                '_HOSTNAME': 6,
                '_UID': 7,
                '_GID': 8,
                '_PID': 9,
                '_EXE': 10,
                '_CMDLINE': 11 }

    def __init__(self):
        self.elephant = journal.Reader()
        self.house = sqlite3.connect('house.db')
        self.room = self.house.cursor()
        self.room.execute(''' CREATE TABLE
                              IF NOT EXISTS
                              GOOROOM_SECURITY_LOG (
                                  __REALTIME_TIMESTAMP TEXT,
                                  PRIORITY             TEXT,
                                  MESSAGE              TEXT,
                                  GRMCODE              TEXT,
                                  SYSLOG_IDENTIFIER    TEXT,
                                  _TRANSPORT           TEXT,
                                  _HOSTNAME            TEXT,
                                  _UID                 TEXT,
                                  _GID                 TEXT,
                                  _PID                 TEXT,
                                  _EXE                 TEXT,
                                  _CMDLINE             TEXT) ''')
        self.targets = dict() 

    def work(self):
        self.crawl()
        self.sniff(identifier=True)
        self.bite(identifier=True)
        self.sniff(identifier=False)
        self.bite(identifier=False)

    def crawl(self):
        print("crwaling")
        self.room.execute(''' SELECT * FROM GOOROOM_SECURITY_LOG
                              ORDER BY __REALTIME_TIMESTAMP
                              DESC LIMIT 1 ''')
        prey = self.room.fetchone()
        if prey:
            self.lasttime = datetime.datetime.strptime(prey[0],'%Y-%m-%d %H:%M:%S.%f')
            self.lasttime += datetime.timedelta(microseconds=1)
        else:
            self.lasttime = datetime.datetime.now()
        print(self.lasttime)
        self.elephant.seek_realtime(1)
        #self.elephant.seek_realtime(self.lasttime)

    def sniff(self, identifier):
        self.elephant.flush_matches()
        if identifier:
            wanted = load_log_config(mode='DAEMON')
            self.targets = syslog_identifier_map(wanted)
            for target, targetname in self.targets.items():
                self.elephant.add_match(SYSLOG_IDENTIFIER=target)
        else:
            self.elephant.add_match(_TRANSPORT='kernel')

    def bite(self, identifier):
        print("biting")
        for flesh in self.elephant:
            if '_KERNEL_SUBSYSTEM' in flesh.keys():
                continue
            prey = ['']*len(self.feature)
            for k, v in self.feature.items():
                prey[v] = flesh[k] if k in flesh else ''
            
            message = flesh['MESSAGE']
            if identifier:
                if type(message) is bytes:
                    prey[self.feature['MESSAGE']] = str(message.decode('unicode_escape').encode('utf-8'))

                if not prey[self.feature['GRMCODE']]:
                    res = re.search(g_gop_regex, message)
                    if res:
                        prey[self.feature['GRMCODE']] = res.group().split('=')[1]
            elif 'kernel' in prey[self.feature['_TRANSPORT']]:
                if GRAC_NETWORK_NAME in message:
                    prey[self.feature['GRMCODE']] = '001001'
                else:
                    search_cause = P_CAUSE.search(message)
                    search_file = P_FILE.search(message)
                    if search_cause is None or search_file is None:
                        continue
                    else:
                        prey[self.feature['GRMCODE']] = '001002'

            print()
            for k,v in self.feature.items():
                print('{}: {}'.format(k, prey[v]))
            print()
            self.drag(prey)

    def drag(self, prey):
        print("dragging")
        command = ''' INSERT INTO GOOROOM_SECURITY_LOG (
                                      __REALTIME_TIMESTAMP,
                                      PRIORITY,
                                      MESSAGE,
                                      GRMCODE,
                                      SYSLOG_IDENTIFIER,
                                      _TRANSPORT,
                                      _HOSTNAME,
                                      _UID,
                                      _GID,
                                      _PID,
                                      _EXE,
                                      _CMDLINE)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?,?) '''
        self.room.execute(command, (prey[self.feature['__REALTIME_TIMESTAMP']],
                                    prey[self.feature['PRIORITY']],
                                    prey[self.feature['MESSAGE']],
                                    prey[self.feature['GRMCODE']],
                                    prey[self.feature['SYSLOG_IDENTIFIER']],
                                    prey[self.feature['_TRANSPORT']],
                                    prey[self.feature['_HOSTNAME']],
                                    prey[self.feature['_UID']],
                                    prey[self.feature['_GID']],
                                    prey[self.feature['_PID']],
                                    prey[self.feature['_EXE']],
                                    prey[self.feature['_CMDLINE']]))
        self.store()

    def store(self):
        print("storing")
        self.house.commit()

    def rest(self):
        self.house.close()


if __name__ == "__main__":
    logant = LogAnt()

    while True:
        logant.work()
        time.sleep(5)

    logant.rest()
