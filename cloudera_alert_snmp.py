#!/usr/bin/env python

"""
Docs about obtaining Cloudera MIB file
https://docs.cloudera.com/cloudera-manager/7.4.2/monitoring-and-diagnostics/topics/cm-alerts-snmp.html
"""

from json import load
# from shutil import copy2
try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser
from dateutil.parser import isoparse
from re import findall
from pysnmp.hlapi import (
    sendNotification,
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    NotificationType,
    ObjectIdentity,
)
from struct import pack
import sys
import os
import logging

logging.basicConfig()
logger = logging.getLogger(os.path.basename(__file__))
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

MAP_NOTIFICATION_CATEGORY = {
    "UNKNOWN": 0,
    "HEALTH_CHECK": 1,
    "LOG_MESSAGE": 2,
    "AUDIT_EVENT": 3,
    "ACTIVITY_EVENT": 4,
    "HBASE": 5,
    "SYSTEM": 6,
}
MAP_EVENT_SEVERITY = {"UNKNOWN": 0, "INFORMATIONAL": 1, "IMPORTANT": 2, "CRITICAL": 3}


def match_severity(severity):
    if t_conf["severity"] == severity:
        logger.debug(
            'Matched severity "%s" against "%s" - passing it trough',
            severity,
            t_conf["severity"],
        )
        return True
    logger.debug(
        'Not matched severity "%s" against "%s" - blacklisting',
        severity,
        t_conf["severity"],
    )
    return False


def match_health(previuos, current):
    if previuos == current:
        logger.debug(
            'PREVIOUS_HEALTH_SUMMARY same as CURRENT_HEALTH_SUMMARY "%s" - blacklisting',
            current,
        )
        return False
    logger.debug(
        "PREVIOUS_HEALTH_SUMMARY is different from CURRENT_HEALTH_SUMMARY - passing it trough"
    )
    return True


def match_suppress(suppress_flag):
    if suppress_flag == "true":
        logger.debug("The message is suppressed - blacklisting")
        return False
    logger.debug("The message is not suppressed - passing it trough")
    return True


def match_service(service):
    if t_conf["service_bl"] == "":
        logger.debug("Service blacklist is empty - passing it trough")
        return True
    elif findall(t_conf["service_bl"], service):
        logger.debug(
            "Matched Service %s against %s - blackisting", service, t_conf["service_bl"]
        )
        return False
    logger.debug(
        "Not matched Service %s against %s - passing it trough",
        service,
        t_conf["service_bl"],
    )
    return True


def match_message(message):
    if t_conf["message_bl"] == "":
        logger.debug("Message blacklist is empty - passing it trough")
        return True
    elif findall(t_conf["message_bl"], message):
        logger.debug(
            'Matched message "%s" against "%s" - blacklisting',
            message,
            t_conf["message_bl"],
        )
        return False
    logger.debug(
        'Not matched message "%s" against "%s" - passing it trough',
        message,
        t_conf["message_bl"],
    )
    return True


def filter_alert(alert):
    attributes = alert["body"]["alert"]["attributes"]
    logger.info(
        'Received %s alert for service "%s" with UUID "%s"',
        attributes["SEVERITY"][0],
        attributes["SERVICE_TYPE"][0],
        attributes["__uuid"][0],
    )
    if (
        match_severity(attributes["SEVERITY"][0])
        and match_health(
            attributes["PREVIOUS_HEALTH_SUMMARY"][0],
            attributes["CURRENT_HEALTH_SUMMARY"][0],
        )
        and match_suppress(attributes["ALERT_SUPPRESSED"][0])
        and match_service(attributes["SERVICE_TYPE"][0])
        and match_message(attributes["HEALTH_TEST_RESULTS"][0]["content"])
    ):
        ts = isoparse(alert["body"]["alert"]["timestamp"]["iso8601"])
        snmp_time = pack(
            ">HBBBBBB", ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second, 0
        )
        dic_res = {
            ("CLOUDERA-MANAGER-MIB", "notifEventId"): attributes["__uuid"][0],
            ("CLOUDERA-MANAGER-MIB", "notifEventOccurredTime"): snmp_time,
            ("CLOUDERA-MANAGER-MIB", "notifEventContent"): attributes[
                "HEALTH_TEST_RESULTS"
            ][0]["content"],
            (
                "CLOUDERA-MANAGER-MIB",
                "notifEventCategory",
            ): MAP_NOTIFICATION_CATEGORY[attributes["CATEGORY"][0]],
            ("CLOUDERA-MANAGER-MIB", "notifEventSeverity"): MAP_EVENT_SEVERITY[
                attributes["SEVERITY"][0]
            ],
            ("CLOUDERA-MANAGER-MIB", "notifEventUrl"): alert["body"]["alert"]["source"],
            ("CLOUDERA-MANAGER-MIB", "notifEventService"): attributes["SERVICE_TYPE"][
                0
            ],
            ("CLOUDERA-MANAGER-MIB", "notifEventCode"): attributes["EVENTCODE"][0],
        }
        try:
            dic_res[("CLOUDERA-MANAGER-MIB", "notifEventHost")] = ";".join(
                attributes["HOSTS"]
            )
            logger.debug(
                'Host(s) "%s" mentioned in alert', ";".join(attributes["HOSTS"])
            )
        except KeyError:
            logger.debug("No hosts mentioned in alert")
        logger.info(
            'Passed trough %s alert for service "%s" with UUID "%s"\n',
            attributes["SEVERITY"][0],
            attributes["SERVICE_TYPE"][0],
            attributes["__uuid"][0],
        )
        return dic_res
    else:
        logger.info(
            'Blacklisted %s alert for service "%s" with UUID "%s"\n',
            attributes["SEVERITY"][0],
            attributes["SERVICE_TYPE"][0],
            attributes["__uuid"][0],
        )


def send_trap(alert):
    iterator = sendNotification(
        SnmpEngine(),
        CommunityData(t_conf["community"]),
        UdpTransportTarget((t_conf["addr"], t_conf["port"])),
        ContextData(),
        "trap",
        NotificationType(
            ObjectIdentity(
                "CLOUDERA-MANAGER-MIB", "clouderaManagerAlert"
            ).addMibSource(t_conf["MIB_SOURCE"]),
            objects=alert,
        ),
    )

    logger.info(
        'Sending SNMP alert for service "%s" with UUID "%s" to trap %s:%s',
        alert[("CLOUDERA-MANAGER-MIB", "notifEventService")],
        alert[("CLOUDERA-MANAGER-MIB", "notifEventId")],
        t_conf["addr"],
        t_conf["port"],
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        logger.info(errorIndication)


if __name__ == "__main__":
    ini_path = os.path.dirname(__file__) + "/cloudera_alert_snmp.ini"
    t_conf = {}
    config = ConfigParser()
    config.read(ini_path)
    t_conf["addr"] = config.get("trap", "ipaddr")
    t_conf["port"] = config.get("trap", "port")
    t_conf["community"] = config.get("trap", "community")
    t_conf["service_bl"] = config.get("filters", "service_blacklist")
    t_conf["message_bl"] = config.get("filters", "messages_blackist")
    t_conf["severity"] = config.get("filters", "alert_severity")
    t_conf["MIB_SOURCE"] = config.get("general", "MIB_SOURCE")

    try:
        sys.argv[1]
        # copy2(sys.argv[1], os.path.dirname(__file__) + '/alerts')
    except IndexError:
        print("Useage:", os.path.basename(__file__), "file_to_read_alerts_of.json")
        exit(1)
    try:
        JSON = load(open(sys.argv[1]))
    except:
        print("No file found", sys.argv[1])
        exit(1)
    filtered = [y for y in (filter_alert(x) for x in JSON) if y is not None]
    list(map(send_trap, filtered))
