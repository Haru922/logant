#! /usr/bin/env python3

#-----------------------------------------------------------------------
import sys
sys.path.append('/usr/lib/gooroom-security-utils')

import configparser
import simplejson as json
import subprocess
import importlib
import datetime
import sqlite3
import os
import re


from gsl_util import combine_message,JournalLevel,status_lang_set
from gsl_util import get_run_status,format_exc,load_log_config
from gsl_util import load_translation,syslog_identifier_map
from gsl_util import config_diff_internal
from systemd import journal

#-----------------------------------------------------------------------
g_trans_parser = load_translation()

LOGANT_CONF = '/usr/lib/gooroom-security-utils/logant.conf'

#-----------------------------------------------------------------------
#AGENT is using this function
#Do not move
def config_diff(file_contents):
    """
    return difference from previous config file
    by gooroom-agent
    """

    return config_diff_internal(file_contents)

#-----------------------------------------------------------------------
#GRAC is using this function
#Do not move
def get_notify_level(printname):
    """
    get notify-level in config
    """

    return JournalLevel[load_log_config()[printname]['notify_level']].value

#-----------------------------------------------------------------------
g_gop_regex = re.compile('GRMCODE=\w+')

def identifier_processing(entry, mode, printname, notify_level, result):
    """
    SYSLOG_IDENTIFIER가 있는 로그를 처리
    """

    message = entry['MESSAGE']

    #TRANSLATION
    if entry['GRMCODE']:
    #if grmcode:
        try:
            ko = g_trans_parser.get(entry['GRMCODE'], 'ko')
            message = combine_message(message, ko)
        except:
            pass
    else:
        return 0

    #SAVE
    log = {
        'grmcode':entry['GRMCODE'],
        'level':JournalLevel(entry['PRIORITY']).name,
        'time':str(entry['__REALTIME_TIMESTAMP']),
        'log':'{} {}'.format(entry['__REALTIME_TIMESTAMP'], message),
        'type':status_lang_set(mode, 0),
        'eval_level':notify_level}

    result[printname+'_log'].append(log)

    if entry['PRIORITY'] <= JournalLevel[notify_level].value:
        result[printname+'_status'] = status_lang_set(mode, 'vulnerable')
        result['status_summary'] = status_lang_set(mode, 'vulnerable')
        log['type'] = status_lang_set(mode, 1)

    return 1

#-----------------------------------------------------------------------
GRAC_NETWORK_NAME = 'GRAC: Disallowed Network'
P_SRC_IP = re.compile('SRC=\S*')
P_DST_IP = re.compile('DST=\S*')
P_SRC_PORT = re.compile('SPT=\S*')
P_DST_PORT = re.compile('DPT=\S*')

P_CAUSE = re.compile('cause=\S*')
P_FILE = re.compile('name=\S*')
P_COMM = re.compile('comm=\S*')

KOREAN_TEXT = {
    u'"invalid-hash"' : u'비정상 해시',
    u'"invalid-signature"' : u'비정상 서명',
    u'"missing-hash"' : u'서명 미존재',
    u'"no_label"' : '레이블 미존재',
    u'"IMA-signature-required"' : u'서명 미존재',
    'invalid-hash' : '비정상 해시',
    'invalid-signature' : '비정상 서명',
    'missing-hash' : '서명 미존재',
    'no_label' : '레이블 미존재',
    'IMA-signature-required' : '서명 미존재'}

def no_identifier_processing(entry, mode, result, log_json):
    """
    SYSLOG_IDENTIFIER가 없는 로그를 처리
    :gep,iptables
    """

    message = ''
    printname = ''

    # iptables
    if 'kernel' in entry['_TRANSPORT'] and GRAC_NETWORK_NAME in entry['MESSAGE']:
        '''
        search_src_ip = P_SRC_IP.search(entry['MESSAGE'])
        search_dst_ip = P_DST_IP.search(entry['MESSAGE'])
        search_src_port = P_SRC_PORT.search(entry['MESSAGE'])
        search_dst_port = P_DST_PORT.search(entry['MESSAGE'])

        if (search_src_ip == None or search_src_port == None or
            search_dst_ip == None or search_dst_port == None):
            return 0

        src_ip_string = search_src_ip.group().replace('SRC=', '')
        src_port_string = search_src_port.group().replace('SPT=', '')
        dst_ip_string = search_dst_ip.group().replace('DST=', '')
        dst_port_string = search_dst_port.group().replace('DPT=', '')

        message = \
            '비인가 네트워크 패킷(출발지 {}:{}, 목적지 {}:{})이'\
            '탐지되어 차단하였습니다'.format(
                                        src_ip_string,
                                        src_port_string,
                                        dst_ip_string,
                                        dst_port_string)
        printname = 'media'
        '''
        pass

	# 커널의 IMA에서 남긴 로그
    elif 'kernel' in entry['_TRANSPORT']:
        search_cause = P_CAUSE.search(entry['MESSAGE'])
        search_file = P_FILE.search(entry['MESSAGE'])
        search_comm = P_COMM.search(entry['MESSAGE'])

        if search_cause != None and search_file != None:

            #TEMP NEEDS
            if search_comm and search_comm.group() and 'gnome-control-c' in search_comm.group():
                return 0

            cause_string = search_cause.group().replace('cause=', '')
            if '"' in search_file.group():
                file_string = \
                    search_file.group().replace('name=', '').replace('"', '')
            else:
                file_string = \
                    search_comm.group().replace('comm=', '').replace('"', '')

            # 시간 변환 및 메시지 한글화
            if cause_string in KOREAN_TEXT:
                cause_string = KOREAN_TEXT[cause_string]

            # 로그 추가
            message = '비인가된 실행파일({}, {})이'\
                '실행되어 차단하였습니다'.format(cause_string, file_string)
            printname = 'exe'

    if message:
        notify_level = log_json[printname]['notify_level']
        log = {
            'grmcode':entry['GRMCODE'],
            'level':JournalLevel(entry['PRIORITY']).name,
            'time':str(entry['__REALTIME_TIMESTAMP']),
            'log':'{} {}'.format(entry['__REALTIME_TIMESTAMP'], message),
            'type':status_lang_set(mode, 0),
            'eval_level':notify_level}

        result[printname+'_log'].append(log)

        if entry['PRIORITY'] <= JournalLevel[notify_level].value:
            result[printname+'_status'] = status_lang_set(mode, 'vulnerable')
            result['status_summary'] = status_lang_set(mode, 'vulnerable')
            log['type'] = status_lang_set(mode, 1)

        return 1
    else:
        return 0

#-----------------------------------------------------------------------
def load_entry(conn, mode, from_time):
    c = conn.cursor()

    if mode == 'DAEMON':
        try:
            with open('/var/tmp/GOOROOM-SECURITY-LOGPARSER-AGENT-NEXT-SEEKTIME', 'r') as f:
                from_time = f.readline()
        except:
            pass

    if from_time:
        from_time = datetime.datetime.strptime(from_time, '%Y%m%d-%H%M%S.%f')
        comp_time = datetime.datetime.strftime(from_time, '%Y-%m-%d %H:%M:%S.%f')
        c.execute(''' SELECT * FROM GOOROOM_SECURITY_LOG
                      WHERE __REALTIME_TIMESTAMP >= ? ''', (comp_time,))
    else:
        c.execute('SELECT * FROM GOOROOM_SECURITY_LOG')

    return c

#-----------------------------------------------------------------------
def get_summary(c, mode='DAEMON'):
    """
    보안기능(os,exe,boot,media)의 journal로그를 파싱해서
    요약로그정보를 출력
    """
    if mode == 'DAEMON':
        config = configparser.ConfigParser()
        config.read(LOGANT_CONF)
        gsl_db = config['LOGANT']['GSL_DATABASE']
        conn = sqlite3.connect(gsl_db)
        conn.row_factory = sqlite3.Row
        c = load_entry(conn, mode='DAEMON', from_time='')

    log_json = load_log_config()
    identifier_map = syslog_identifier_map(log_json)

    #identifier and priority
    for identifier, printname in identifier_map.items():

        if mode == 'DAEMON':
            transmit_p = \
                JournalLevel[log_json[printname]['transmit_level']].value
            notify_p = \
                JournalLevel[log_json[printname]['notify_level']].value
            if transmit_p < notify_p:
                level_key = 'notify_level'
            else:
                level_key = 'transmit_level'
        else:
            show_p = \
                JournalLevel[log_json[printname]['show_level']].value
            notify_p = \
                JournalLevel[log_json[printname]['notify_level']].value
            if show_p < notify_p:
                level_key = 'notify_level'
            else:
                level_key = 'show_level'

        log_json[printname]['priority_key'] = JournalLevel[log_json[printname][level_key]].value

    #초기화 및 실행상태, 로그등급
    result = {}
    for identifier, printname in identifier_map.items():
        if 'service_name' in log_json[printname]:
            service_name = log_json[printname]['service_name']
        else:
            service_name = ''
        run = get_run_status(service_name)

        result[printname+'_run'] = status_lang_set(mode, run)
        result[printname+'_status'] = status_lang_set(mode, 'safe')
        result[printname+'_notify_level'] = log_json[printname]['notify_level']
        result[printname+'_show_level'] = log_json[printname]['show_level']
        result[printname+'_log'] = []
    result['status_summary'] = status_lang_set(mode, 'safe')

    log_total_len = 0

    last_entry = None
    for entry in c:
        try:
            printname = ''
            if entry['SYSLOG_IDENTIFIER'] in identifier_map.keys():
                printname = identifier_map[entry['SYSLOG_IDENTIFIER']]
            elif 'kernel' in entry['_TRANSPORT'] and 'shadow-box:' in entry['MESSAGE'][:11]:
                printname = identifier_map[entry['gop-daemon']]

            if printname:
                if log_json[printname]['priority_key'] >= entry['PRIORITY']:
                    notify_level = log_json[printname]['notify_level']
                    log_total_len += \
                        identifier_processing(entry,
                                              mode,
                                              printname,
                                              notify_level,
                                              result)
            else:
                #IMA(gep)
                #OS 보호 및 방화벽 로그를 추려내기위한 특수한 필터
                if entry['SYSLOG_IDENTIFIER'] is 'kernel':
                    if entry['PRIORITY'] == 3 or entry['PRIORITY'] == 5:
                        log_totall_len += \
                            no_identifier_processing(entry, mode, result, log_json)

            #LAST ENTRY
            last_entry = entry
        except:
            print(format_exc())

    result['log_total_len'] = log_total_len

    if last_entry:
        next_seek_time = str(last_entry['__REALTIME_TIMESTAMP'])
        next_seek_time = datetime.datetime.strptime(next_seek_time, '%Y-%m-%d %H:%M:%S.%f') + datetime.timedelta(microseconds=1)

        if mode == 'GUI':
            with open('/var/tmp/GOOROOM-SECURITY-LOGPARSER-NEXT-SEEKTIME', 'w') as f:
                f.write(next_seek_time.strftime('%Y%m%d-%H%M%S.%f'))
        elif mode == 'DAEMON':
            with open('/var/tmp/GOOROOM-SECURITY-LOGPARSER-AGENT-NEXT-SEEKTIME', 'w') as f:
                f.write(next_seek_time.strftime('%Y%m%d-%H%M%S.%f'))

    if mode == 'DAEMON':
        conn.close()

    return result

#-----------------------------------------------------------------------
def get_current_journal_disk_usage():
    """
    return current journal disk usage
    """

    pp = subprocess.Popen(
        ['/bin/journalctl', '--disk-usage'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    pp_out, pp_err = pp.communicate()
    disk_usage = pp_out.decode('utf8').split()[6]
    disk_unit = disk_usage[-1]
    if disk_unit != 'G':
        return 0
    return float(disk_usage[:-1])

#-----------------------------------------------------------------------
def verify_journal_disk_usage():
    """
    if verifying is failed, raise exception
    """

    disk_usage = get_current_journal_disk_usage()
    if disk_usage > 5.0:
        raise Exception('JOURNAL DISK USAGE({}G) '\
            'IS TOO LARGE'.format(disk_usage))

#-----------------------------------------------------------------------
if __name__ == '__main__':

    if os.geteuid():
        sys.exit('gooroom-security-logparser: Permission denied')

    config = configparser.ConfigParser()
    config.read(LOGANT_CONF)
    gsl_db = config['LOGANT']['GSL_DATABASE']
    conn = sqlite3.connect(gsl_db)
    conn.row_factory = sqlite3.Row

    from_time = sys.argv[1] if len(sys.argv) > 1 else ''
    c = load_entry(conn, mode='GUI', from_time=from_time)

    print('JSON-ANCHOR=%s' % json.dumps(
                                get_summary(c, mode='GUI'),
                                ensure_ascii=False,
                                sort_keys=True,
                                indent=4,
                                separators=(',', ': ')))
    conn.close()
