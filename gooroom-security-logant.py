import re
import sys
import time
import signal
import psutil
import sqlite3
import datetime
import importlib
import configparser

from gi.repository import GLib
from systemd import journal

from gsl_util import load_log_config,syslog_identifier_map

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop

LOGANT_CONF = '/usr/lib/gooroom-security-utils/logant.conf'

g_gop_regex = re.compile('GRMCODE=\w+')
GRAC_NETWORK_NAME = 'GRAC: Disallowd Network'
P_CAUSE = re.compile('cause=\S*')
P_FILE = re.compile('name=\S*')

class LogAnt(dbus.service.Object):
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

    def __init__(self, house, targets):
        pheromone = dbus.service.BusName('kr.gooroom.logant', bus=dbus.SystemBus())
        dbus.service.Object.__init__(self, pheromone, '/kr/gooroom/logant')
        self.loop = GLib.MainLoop()
        self.targets = targets
        self.elephant = journal.Reader()
        self.house = sqlite3.connect(house)
        self.room = self.house.cursor()
        self.room.execute(''' CREATE TABLE
                              IF NOT EXISTS
                              GOOROOM_SECURITY_LOG (
                                  __REALTIME_TIMESTAMP TEXT,
                                  PRIORITY             INTEGER,
                                  MESSAGE              TEXT,
                                  GRMCODE              TEXT,
                                  SYSLOG_IDENTIFIER    TEXT,
                                  _TRANSPORT           TEXT,
                                  _HOSTNAME            TEXT,
                                  _UID                 INTEGER,
                                  _GID                 INTEGER,
                                  _PID                 INTEGER,
                                  _EXE                 TEXT,
                                  _CMDLINE             TEXT) ''')
        self.lasttime = datetime.datetime.now()

    def start(self):
        self.loop.run()

    def work(self):
        self.crawl()
        self.sniff(identifier=True)
        self.bite(identifier=True)
        self.sniff(identifier=False)
        self.bite(identifier=False)
        return True

    def crawl(self):
        self.room.execute(''' SELECT * FROM GOOROOM_SECURITY_LOG
                              ORDER BY __REALTIME_TIMESTAMP
                              DESC LIMIT 1 ''')
        prey = self.room.fetchone()
        if prey:
            self.lasttime = datetime.datetime.strptime(prey[0],'%Y-%m-%d %H:%M:%S.%f')
            self.lasttime += datetime.timedelta(microseconds=1)
        self.elephant.seek_realtime(self.lasttime)

    def sniff(self, identifier):
        self.elephant.flush_matches()
        if identifier:
            for target in self.targets:
                self.elephant.add_match(SYSLOG_IDENTIFIER=target.strip())
        else:
            self.elephant.add_match(_TRANSPORT='kernel')

    def bite(self, identifier):
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
                        cause_string = search_cause.group().replace('cause=', '')
                        if cause_string == '"no_label"' and '_AUDIT_FIELD_NAME' in flesh.keys():
                            prey[self.feature['MESSAGE']] = prey[self.feature['MESSAGE']].replace('no_label', flesh['_AUDIT_FIELD_NAME'].replace('"', ''))
                        prey[self.feature['GRMCODE']] = '001002'

            self.drag(prey)

    def drag(self, prey):
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
        self.house.commit()
        self.lasttime = datetime.datetime.now()

    def sleep(self, signum, frame):
        self.house.close()
        self.loop.quit()

    @dbus.service.method(dbus_interface='kr.gooroom.logant', in_signature='s', out_signature='b', sender_keyword='sender')
    def update_next_seektime(self, time, sender=None):
        bus_obj = dbus.SystemBus().get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
        bus_inf = dbus.Interface(bus_obj, dbus_interface='org.freedesktop.DBus')
        pid = bus_inf.GetConnectionUnixProcessID(sender)
        ps = psutil.Process(pid)
        exe = ps.exe()
        cmdline = ps.cmdline()
        script = cmdline[1]
        if exe == '/usr/bin/python3.7' and script == '/usr/bin/gooroom-security-logparser.py':
            with open('/var/tmp/GOOROOM-SECURITY-LOGPARSER-NEXT-SEEKTIME', 'w') as f:
                f.write(time)
        else:
            return False
        return True

if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read(LOGANT_CONF)

    log_json = load_log_config()
    syslog_identifier = [si for si in syslog_identifier_map(log_json).keys()]

    database = config['LOGANT']['GSL_DATABASE']
    break_time = int(config['LOGANT']['BREAK_TIME_SECONDS'])
    DBusGMainLoop(set_as_default=True)

    logant = LogAnt(database, syslog_identifier)
    signal.signal(signal.SIGTERM, logant.sleep)
    GLib.timeout_add_seconds(break_time, logant.work)
    logant.start()
