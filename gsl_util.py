#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import configparser
import subprocess
import traceback
import OpenSSL
import base64
import shlex
import time
import dbus
import re
import os

from systemd import journal

#-----------------------------------------------------------------------
DEFAULT_LOG_CONF_PATH=\
    '/usr/lib/gooroom-security-utils/default-log.conf'
LOG_CONF_PATH=\
    '/usr/lib/gooroom-security-utils/log.conf'
LOG_CONF_SIGN_PATH=\
    '/var/tmp/gooroom-agent-service/.usr.lib.gooroom-security-utils.log.conf/log.conf+signature'
TRANSLATION_PATH=\
    '/usr/lib/gooroom-security-utils/translation'

#-----------------------------------------------------------------------
import enum
class JournalLevel(enum.Enum):
    none =      -1
    emerg =     0
    alert =     1
    crit =      2
    err =       3
    warning =   4
    notice =    5
    info =      6
    debug =     7

#-----------------------------------------------------------------------
STATUS_LANG_SET = { 
    'safe':'안전', 'vulnerable':'취약', 'run':'동작', 
    'stop':'중단', 1:'취약', 0:'안전' }

def status_lang_set(mode, lang):
    """
    상태 문자 번역판
    """

    if mode == 'DAEMON':
        return STATUS_LANG_SET[lang]
    else:
        return lang

#-----------------------------------------------------------------------
def get_run_status(service_name):
    """
    로그와 시스템의 특정 정보를 이용해서 
    안전하게 부팅되었는지 여부를 반환한다.
    """

    if not service_name:
        return 'stop'

    try:
        # 서비스 구동 상태와 정상 설치 여부를 검사
        cmd = '/usr/sbin/service {} status'.format(service_name)
        argv = shlex.split(cmd)
        pipe = subprocess.Popen(
            argv, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            shell=False)
        status_output, error =  pipe.communicate()
        status_output = status_output.decode('utf-8')

        cmd = '/usr/sbin/service {} check'.format(service_name)
        argv = shlex.split(cmd)
        pipe = subprocess.Popen(
            argv, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            shell=False)
        check_output, error =  pipe.communicate()
        check_output = check_output.decode('utf-8')

        if not 'active (exited)' in status_output \
            and not 'active (running)' in status_output:
            return 'stop'

        if service_name != 'grac-device-daemon' \
            and service_name != 'gooroom-agent' \
            and not '{} active.'.format(service_name) in check_output:
                return 'stop'
        return 'run'
    except:
        return 'stop'

#-----------------------------------------------------------------------
def format_exc():
    """
    reprlib version of format_exc of traceback
    """

    return '\n'.join(traceback.format_exc().split('\n')[-4:-1])

#-----------------------------------------------------------------------
def verify_signature(signature, data):
    """
    verify file signature
    """

    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, 
        open('/etc/gooroom/agent/server_certificate.crt').read())

    OpenSSL.crypto.verify(cert, 
        base64.b64decode(signature.encode('utf8')), 
        data.encode('utf8'), 'sha256')

#-----------------------------------------------------------------------
SIGN_LOCK_PATH = '/var/tmp/GOOROOM-SECURITY-UTILS-SIGN-FAIL-LOCK'

DBUS_NAME = 'kr.gooroom.agent'
DBUS_OBJ = '/kr/gooroom/agent'
DBUS_IFACE = 'kr.gooroom.agent'

def do_task():
    """
    send job to agent
    """

    try:
        task = '{"module":{"module_name":"config","task":{"task_name":"get_log_config","in":{}}}}'
        system_bus = dbus.SystemBus()
        bus_object = system_bus.get_object(DBUS_NAME, DBUS_OBJ)
        bus_interface = dbus.Interface(bus_object, dbus_interface=DBUS_IFACE)
        resp = bus_interface.do_task(task)
        print(resp)
    except:
        print(format_exc())

def load_log_config():
    """
    서버설정파일의 로딩에 실패하면
    기본설정파일을 반환.
    기본설정파일의 로딩에 실패하면
    {}을 반환.
    """
    
    global g_sign_fail_cnt
    verify_failed = False
    try:
        with open(LOG_CONF_PATH) as f2:
            log_string = f2.read()
        with open(LOG_CONF_SIGN_PATH) as f3:
            log_sign = f3.read()

        verify_signature(log_sign, log_string)
        if os.path.exists(SIGN_LOCK_PATH):
            os.remove(SIGN_LOCK_PATH)
        return json.loads(log_string)
    except:
        pass
        
    try:
        with open(DEFAULT_LOG_CONF_PATH) as f:
            l = json.loads(f.read())
            return l
    except:
        print(format_exc())

    return {}

#-----------------------------------------------------------------------
def load_translation():
    """
    번역파일을 로딩
    """

    parser = configparser.RawConfigParser()
    parser.optionxform = str
    parser.read(TRANSLATION_PATH)
    return parser

#-----------------------------------------------------------------------
def combine_message(message, ko):
    """
    메세지 안에 있는 토큰을 분리해서 번역문을 완성한다
    """

    try:
        token_regix = re.compile('\$\(.+?\)', re.DOTALL)

        tokens = token_regix.findall(message)
        msg_values = []
        for token in tokens:
            msg_values.append(token[2:-1])

        ko_regix = re.compile('\$\(\d+\)')
        holders = ko_regix.findall(ko)
        for holder in holders:
            idx = int(holder[2:-1])
            ko = ko.replace(holder, msg_values[idx])

        return ko
    except:
        print(format_exc())
        print('failed message===>{}\t{}'.format(message, ko))
        raise
                
#-----------------------------------------------------------------------
def syslog_identifier_map(log_json):
    """
    로그설정에서 syslog_identifier 리스트를 반환
    """

    d = {}
    for printname, infos in log_json.items():
        identifiers = [ifs.strip() 
                        for ifs in infos['syslog_identifier'].split(',')]
        for identifier in identifiers:
            d[identifier] = printname
    return d

#-----------------------------------------------------------------------
def config_diff_internal(file_contents):
    """
    return difference from previous config file
    by gooroom-agent
    """

    diff_result = ''

    if not os.path.exists(LOG_CONF_PATH):
        return diff_result

    with open(LOG_CONF_PATH, 'r') as f:
        old_contents = json.loads(f.read())
    new_contents = json.loads(file_contents)

    for old_k, old_v in old_contents.items():
        if not old_k in new_contents:
            continue
        new_v = new_contents[old_k]
        for n in ('notify_level', 'show_level', 'transmit_level'):
            if old_v[n] != new_v[n]:
                diff_result += '{} {} {}->{} '.format(
                                                    old_k,
                                                    n,
                                                    old_v[n],
                                                    new_v[n])
    if diff_result:
        diff_result = \
            'log configuration has changed$({})'.format(diff_result)
    return diff_result

