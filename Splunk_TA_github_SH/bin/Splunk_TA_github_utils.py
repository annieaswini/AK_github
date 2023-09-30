#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

"""
This module has utility functions for fectching account details, checkpointing,
writng events to splunk, setting loggers, input validations etc.
"""
import json
import os  # noqa: F401
import os.path as op
import sys
import traceback

import requests

# isort: off
import splunk.admin as admin
import import_declare_test  # noqa: F401
from solnlib import conf_manager, log
from solnlib.modular_input import checkpointer
from splunklib import modularinput as smi
from splunktaucclib.rest_handler.endpoint.validator import Validator

APP_NAME = __file__.split(op.sep)[-3]

_LOGGER = log.Logs().get_logger("Splunk_TA_github_utils")

CHECKPOINTER = "Splunk_TA_github_checkpointer"


def get_log_level(session_key):
    """
    This function returns the log level for the addon from configuration file
    :return: The log level configured for the addon
    """

    try:
        cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-splunk_ta_github_settings".format(
                APP_NAME
            ),
        )
        conf = cfm.get_conf("splunk_ta_github_settings")
        logging_details = conf.get("logging")
        return logging_details["loglevel"]
    except Exception:
        return "DEBUG"


def set_logger(session_key, filename):
    """
    This function sets up a logger with configured log level.
    :param filename: Name of the log file
    :return logger: logger object
    """

    log_level = get_log_level(session_key)
    logger = log.Logs().get_logger(filename)
    logger.setLevel(log_level)
    return logger


def get_proxy_settings(logger, session_key):
    """
    This function reads proxy settings if any, otherwise returns None
    :param session_key: Session key for the particular modular input
    :return: A dictionary proxy having settings
    """

    try:
        settings_cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-splunk_ta_github_settings".format(
                APP_NAME
            ),
        )
        splunk_ta_github_settings_conf = settings_cfm.get_conf(
            "splunk_ta_github_settings"
        ).get_all()

        proxy_settings = None
        proxy_stanza = {}
        for key, value in splunk_ta_github_settings_conf["proxy"].items():
            proxy_stanza[key] = value

        if int(proxy_stanza.get("proxy_enabled", 0)) == 0:
            logger.info("Proxy is disabled. Returning None")
            return proxy_settings
        proxy_port = proxy_stanza.get("proxy_port")
        proxy_url = proxy_stanza.get("proxy_url")
        proxy_type = proxy_stanza.get("proxy_type")
        proxy_username = proxy_stanza.get("proxy_username", "")
        proxy_password = proxy_stanza.get("proxy_password", "")

        if proxy_type == "socks5":
            proxy_type += "h"
        if proxy_username and proxy_password:
            proxy_username = requests.compat.quote_plus(proxy_username)
            proxy_password = requests.compat.quote_plus(proxy_password)
            proxy_uri = "%s://%s:%s@%s:%s" % (
                proxy_type,
                proxy_username,
                proxy_password,
                proxy_url,
                proxy_port,
            )
        else:
            proxy_uri = "%s://%s:%s" % (proxy_type, proxy_url, proxy_port)

        proxy_settings = {"http": proxy_uri, "https": proxy_uri}
        logger.info("Successfully fetched configured proxy details.")
        return proxy_settings

    except Exception:
        logger.error(
            "Failed to fetch proxy details from configuration. {}".format(
                traceback.format_exc()
            )
        )
        sys.exit(1)


def get_account_details(logger, session_key, account_name):
    """
    This function retrieves account details from addon configuration file
    :param session_key: Session key for the particular modular input
    :param account_name: Account name configured in the addon
    :return: Account details in form of a dictionary
    """

    try:
        cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-splunk_ta_github_account".format(
                APP_NAME
            ),
        )
        account_conf_file = cfm.get_conf("splunk_ta_github_account")
        logger.debug(
            "Getting personal access token from splunk_ta_github_account.conf for account name {}".format(  # noqa: E501
                account_name
            )
        )

        return {
            "security_token": account_conf_file.get(account_name).get("security_token"),
        }
    except Exception:
        logger.error(
            "Failed to fetch the account details from splunk_ta_github_account.conf file for the account: {}".format(  # noqa: E501
                account_name
            )
        )
        sys.exit("Error while fetching account details. Terminating modular input.")


def write_event(logger, event_writer, raw_event, sourcetype, input_params):
    """
    This function ingests data into splunk
    :param event_writer: Event Writer object
    :param raw_event: Raw event to be ingested into splunk
    :param sourcetype: Sourcetype of the data
    :param input_params: Input parameters configured by user
    :param manager_url: URL which is getting used to fetch events
    :return: boolean value indicating if the event is successfully ingested
    """

    try:
        event = smi.Event(
            data=json.dumps(raw_event),
            sourcetype=sourcetype,
            source=input_params["name"].replace("://", ":")
            + ":"
            + input_params["account"],
            index=input_params["index"],
        )
        event_writer.write_event(event)
        return True
    except Exception:
        logger.error("Error writing event to Splunk: {}".format(traceback.format_exc()))
        return False


class GetSessionKey(admin.MConfigHandler):
    def __init__(self):
        self.session_key = self.getSessionKey()


# jscpd:ignore-start
class ValidateAuditInput(Validator):
    """
    Check if the Organization/Enterprise name provided is correct or not.
    """

    def __init__(self, *args, **kwargs):
        super(ValidateAuditInput, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        session_key = GetSessionKey().session_key
        account_details = get_account_details(_LOGGER, session_key, data.get("account"))
        proxy_settings = get_proxy_settings(_LOGGER, session_key)
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(account_details["security_token"]),
        }
        if data.get("org_name"):
            try:
                api_url = "https://api.github.com/orgs/{}".format(str(value))
                resp = requests.get(
                    url=api_url, proxies=proxy_settings, headers=headers
                )
                if resp.status_code in (200, 201):
                    new_api_url = "https://api.github.com/orgs/{}/audit-log".format(
                        str(value)
                    )
                    new_resp = requests.get(
                        url=new_api_url, proxies=proxy_settings, headers=headers
                    )
                    if new_resp.status_code in (200, 201):
                        return True
                    else:
                        _LOGGER.error(
                            "ERROR [{}] while validating Audit Log Input for Organization. - Response = {}".format(
                                new_resp.status_code, new_resp.json()
                            )
                        )
                        if new_resp.status_code in (403, 401):
                            self.put_msg(new_resp.json()["message"])
                        elif new_resp.status_code == 404:
                            self.put_msg(
                                "Provided organization does not have access to collect audit data."
                            )
                        else:
                            self.put_msg(
                                "Unable to configure the input. Check logs for more details."
                            )
                        return False
                else:
                    _LOGGER.error(
                        "ERROR [{}] while validating Audit Log Input for Organization. - Response = {}".format(
                            resp.status_code, resp.json()
                        )
                    )
                    if resp.status_code in (403, 401):
                        self.put_msg(resp.json()["message"])
                    elif resp.status_code == 404:
                        self.put_msg("Invalid Organization Name")
                    else:
                        self.put_msg(
                            "Unable to configure the input. Check logs for more details."
                        )
                    return False
            except Exception:
                _LOGGER.error("Failed to connect. {}".format(traceback.format_exc()))
                msg = "Could not connect to GitHub. Check configuration and network settings"
                self.put_msg(msg)
        if data.get("enterprises_name"):
            try:
                api_url = "https://api.github.com/enterprises/{}/audit-log".format(
                    str(value)
                )
                resp = requests.get(
                    url=api_url, proxies=proxy_settings, headers=headers
                )
                if resp.status_code in (200, 201):
                    return True
                else:
                    _LOGGER.error(
                        "ERROR [{}] while validating Audit Log Input for Enterprise. - Response = {}".format(
                            resp.status_code, resp.json()
                        )
                    )
                    if resp.status_code in (403, 401, 404):
                        self.put_msg(
                            "Enterprise doesn't exist or Enterprise does not have access to collect audit data."
                        )
                    else:
                        self.put_msg(
                            "Unable to configure the input. Check logs for more details."
                        )
                    return False
            except Exception:
                _LOGGER.error("Failed to connect. {}".format(traceback.format_exc()))
                msg = "Could not connect to GitHub. Check configuration and network settings"
                self.put_msg(msg)
        return False


class ValidateUserInput(Validator):
    """
    Check if the Organization name provided is correct or not.
    """

    def __init__(self, *args, **kwargs):
        super(ValidateUserInput, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        session_key = GetSessionKey().session_key
        account_details = get_account_details(_LOGGER, session_key, data.get("account"))
        proxy_settings = get_proxy_settings(_LOGGER, session_key)
        if data.get("org_name"):
            try:
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer {}".format(
                        account_details["security_token"]
                    ),
                }
                api_url = "https://api.github.com/orgs/{}".format(str(value))

                resp = requests.get(
                    url=api_url, proxies=proxy_settings, headers=headers
                )
                if resp.status_code in (200, 201):
                    return True
                else:
                    _LOGGER.error(
                        "ERROR [{}] while validating User Input for Organization. - Response = {}".format(
                            resp.status_code, resp.json()
                        )
                    )
                    if resp.status_code in (401, 403):
                        self.put_msg(resp.json()["message"])
                    elif resp.status_code == 404:
                        self.put_msg("Invalid Organization Name")
                    else:
                        self.put_msg(
                            "Unable to configure the input. Check logs for more details."
                        )
                    return False
            except Exception:
                _LOGGER.error("Failed to connect. {}".format(traceback.format_exc()))
                msg = "Could not connect to GitHub. Check configuration and network settings"
                self.put_msg(msg)
        return False


# jscpd:ignore-end


def checkpoint_handler(logger, session_key, check_point_value, check_point_key):
    """
    Handles checkpoint
    """
    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            CHECKPOINTER, session_key, APP_NAME
        )
        logger.debug(
            "Trying to get checkpoint for the input : {}".format(check_point_key)
        )
        checkpoint_dict = checkpoint_collection.get(check_point_key)  # noqa: F841
    except Exception:
        logger.error("Error in Checkpoint handling : {}".format(traceback.format_exc()))

    try:
        logger.info("Updating {} as checkpoint value".format(check_point_value))
        checkpoint_collection.update(check_point_key, check_point_value)
    except Exception as e:
        logger.error("Updating checkpoint failed. Exception occurred : {}".format(e))


def delete_checkpoint(logger, session_key, checkpoint_key):
    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            CHECKPOINTER, session_key, APP_NAME
        )
        checkpoint_collection.delete(checkpoint_key)
    except Exception as e:
        logger.error("Error occured while deleting checkpoint: {}".format(e))
