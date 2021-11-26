#!/usr/bin/python

"""
Docs about obtaining Cloudera MIB file
https://docs.cloudera.com/cloudera-manager/7.4.2/monitoring-and-diagnostics/topics/cm-alerts-snmp.html
"""
from json import load
from configparser import ConfigParser
from dateutil.parser import isoparse
from pathlib import Path
from re import match, search
from pysnmp.hlapi import (sendNotification, SnmpEngine, CommunityData,
UdpTransportTarget, ContextData, NotificationType, ObjectIdentity)
from struct import pack
import sys
import os


def send_trap(alerts, t_conf):
    for alert in alerts:
        iterator = sendNotification(
            SnmpEngine(),
            CommunityData(t_conf['community']),
            UdpTransportTarget((t_conf['addr'], t_conf['port'])),
            ContextData(),
            'trap',
            NotificationType(
                ObjectIdentity('CLOUDERA-MANAGER-MIB', 'clouderaManagerAlert').addMibSource(str(Path.home) + '.pysnmp/mibs'),
                objects=alert
            )
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            print(errorIndication)


def iterate_alerts(json, severity):

    MAP_NOTIFICATION_CATEGORY = {
        "UNKNOWN": 0,
        "HEALTH_CHECK": 1,
        "LOG_MESSAGE": 2,
        "AUDIT_EVENT": 3,
        "ACTIVITY_EVENT": 4,
        "HBASE": 5,
        "SYSTEM": 6
    }
    MAP_EVENT_SEVERITY = {
        "UNKNOWN": 0,
        "INFORMATIONAL": 1,
        "IMPORTANT": 2,
        "CRITICAL": 3
    }

    filtered = []
    for item in json:
        attributes = item['body']['alert']['attributes']
        # print(item['body']['alert']['source'])
        # print(item['body']['alert']['timestamp']['iso8601'])
        # print(attributes['PREVIOUS_HEALTH_SUMMARY'])
        # print(attributes['CURRENT_HEALTH_SUMMARY'])
        # print(attributes['SERVICE_TYPE'][0])
        # print(attributes['SERVICE'][0])
        # print(attributes['__uuid'][0])
        # print(attributes['HEALTH_TEST_RESULTS'][0]['content'])
        # print(attributes['EVENTCODE'])
        # print(attributes['SEVERITY'][0])
        # print(attributes['CATEGORY'][0])
        # print(attributes['ALERT_SUPPRESSED'][0])
        # print(t_conf['service_bl'])

        if (
            attributes['PREVIOUS_HEALTH_SUMMARY'] != attributes['CURRENT_HEALTH_SUMMARY']
            and attributes['SEVERITY'][0] == severity
            and not match(t_conf['service_bl'], attributes['SERVICE_TYPE'][0])
            and not search(t_conf['messages'], attributes['HEALTH_TEST_RESULTS'][0]['content'])
            and not attributes['ALERT_SUPPRESSED'][0] == "true"
        ):
            ts = isoparse(item['body']['alert']['timestamp']['iso8601'])
            snmp_time = pack('>HBBBBBB', ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second, 0)
            dic_res = {
                ('CLOUDERA-MANAGER-MIB', 'notifEventId'): attributes['__uuid'][0],
                ('CLOUDERA-MANAGER-MIB', 'notifEventOccurredTime'): snmp_time,
                ('CLOUDERA-MANAGER-MIB', 'notifEventContent'): attributes['HEALTH_TEST_RESULTS'][0]['content'],
                ('CLOUDERA-MANAGER-MIB', 'notifEventCategory'): MAP_NOTIFICATION_CATEGORY[attributes['CATEGORY'][0]],
                ('CLOUDERA-MANAGER-MIB', 'notifEventSeverity'): MAP_EVENT_SEVERITY[attributes['SEVERITY'][0]],
                ('CLOUDERA-MANAGER-MIB', 'notifEventUrl'): item['body']['alert']['source'],
                ('CLOUDERA-MANAGER-MIB', 'notifEventService'): attributes['SERVICE_TYPE'][0],
                ('CLOUDERA-MANAGER-MIB', 'notifEventCode'): attributes['EVENTCODE'][0]
                }
            try:
                dic_res[('CLOUDERA-MANAGER-MIB', 'notifEventHost')] = attributes['HOSTS'][0]
            except KeyError:
                pass
            filtered.append(dic_res)

    return(filtered)


if __name__ == '__main__':
    ini_path = os.path.dirname(__file__) + '/cloudera_alert_snmp.ini'
    t_conf = {}
    config = ConfigParser()
    config.read(ini_path)
    t_conf['addr'] = config.get('trap', 'ipaddr')
    t_conf['port'] = config.get('trap', 'port')
    t_conf['community'] = config.get('trap', 'community')
    t_conf['service_bl'] = config.get('filters', 'service_blacklist')
    t_conf['messages'] = config.get('filters', 'messages_blackist')
    t_conf['severity'] = config.get('filters', 'alert_severity')

    try:
        sys.argv[1]
    except IndexError:
        print("Useage:", os.path.basename(__file__), "file_to_read_alerts_of.json")
        exit(1)
    try:
        JSON = load(open(sys.argv[1]))
    except:
        print("No file found", sys.argv[1])
        exit(1)
    a = iterate_alerts(JSON, t_conf['severity'])
    send_trap(a, t_conf)

# DONE Alerts should be enumerated or iterated trough
# DONE Alerts should be filtered by SEVERITY, Which alerts are pass trough defined by a configuration
# DONE CURRENT_HEALTH_SUMMARY should be different from PREVIOUS_HEALTH_SUMMARY
# DONE Alerts should be filtered by service
# DONE Alerts should be filtered by keyword in message
# DONE Suppressed alerts should be filtered out
# TODO (Optional) Alerts should be filtered by CLUSTER
# TODO (Optional) Add looping over multiple messages if there are present
# TODO Add tests
# TODO Add logging
