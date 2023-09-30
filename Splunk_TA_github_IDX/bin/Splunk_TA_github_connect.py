#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

"""
This module contains all rest calls to GitHub
"""

import traceback

import requests

# isort: off
import import_declare_test  # noqa: F401
import os  # noqa: F401
import os.path as op
from Splunk_TA_github_utils import (
    write_event,
    checkpoint_handler,
)
from urllib.parse import urlparse, parse_qs
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from splunktaucclib.rest_handler.error import RestError
from solnlib.modular_input import checkpointer

APP_NAME = __file__.split(op.sep)[-3]

CHECKPOINTER = "Splunk_TA_github_checkpointer"

PER_PAGE = 100


class GitHubConnect:
    """
    This class contains does and handles the API calls for data collection
    """

    def __init__(self, config):

        self.security_token = config["security_token"]
        self.proxies = config["proxies"]
        self.session_key = config["session_key"]
        self.input_params = config["input_params"]
        self._logger = config["logger"]
        self.account_name = config["account_name"]

    def collect_audit_data(self, account_type, org_name, event_writer):
        error_flag_for_audit_data = 0
        collect_data = 0
        api_url = "https://api.github.com"

        slug = "/{type}/{enterprise}/audit-log".replace("{type}", account_type).replace(
            "{enterprise}", org_name
        )
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(self.security_token),
        }
        event_counter = 0
        checkpoint_key = self.input_params["name"]
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            CHECKPOINTER, self.session_key, APP_NAME
        )
        checkpoint_value = checkpoint_collection.get(checkpoint_key)
        next_hash = ""
        last = 0
        if checkpoint_value:
            # This block of code would be executed if the checkpoints exists
            self._logger.debug(
                "Checkpoint for {} exists with value {}".format(
                    checkpoint_key, checkpoint_value
                )
            )
            last_count = checkpoint_value["last_count"]
            last_after = checkpoint_value["last_after"]
            params = {
                "phrase": "",
                "include": self.input_params["events_type"],
                "after": last_after,
                "before": "",
                "order": "asc",
                "per_page": str(PER_PAGE),
            }
            response = requests.get(
                "{}{}".format(api_url, slug),
                headers=headers,
                proxies=self.proxies,
                params=params,
            )
            if response.ok:
                if last_count == PER_PAGE:
                    self._logger.debug(
                        "Last count {}, checking for next hash value.".format(
                            last_count
                        )
                    )
                    collect_data = 1
                    if "next" in response.links:
                        next_hash = parse_qs(
                            urlparse(response.links["next"]["url"]).query
                        )["after"][0]
                        self._logger.debug("next_hash value has been found.")
                        checkpoint_value = {
                            "last_count": 0,
                            "last_after": next_hash,
                        }
                        checkpoint_handler(
                            self._logger,
                            self.session_key,
                            checkpoint_value,
                            checkpoint_key,
                        )
                    else:
                        last = 1

                if last_count >= len(response.json()) and last_count != PER_PAGE:
                    self._logger.debug(
                        "Last count {} equal to entries length {}".format(
                            last_count, len(response.json())
                        )
                    )
                    self._logger.info(
                        "No new events found. All the events are successfully ingested"
                    )
                    last = 1
                elif collect_data != 1:
                    entries = []
                    last_event = 0
                    for entry in response.json():
                        entries.append(entry)
                        if last_count < len(entries):
                            # Write event only when count of ingested events is less than the total number of events
                            event_written = write_event(
                                self._logger,
                                event_writer,
                                entry,
                                "github:cloud:audit",
                                self.input_params,
                            )
                            if not event_written:
                                last_event = 1
                                break
                            event_counter += 1
                    checkpoint_value = {
                        "last_count": len(entries) - last_event,
                        "last_after": last_after,
                    }
                    checkpoint_handler(
                        self._logger, self.session_key, checkpoint_value, checkpoint_key
                    )
                    if "next" in response.links and last_event != 1:
                        next_hash = parse_qs(
                            urlparse(response.links["next"]["url"]).query
                        )["after"][0]
                    else:
                        last = 1
                        self._logger.info(
                            "Successfully ingested {} audit events.".format(
                                event_counter
                            )
                        )
            # jscpd:ignore-start
            else:
                raise RuntimeError(
                    "Could not fetch audit log data. Please check your configuration, \
                         access token scope / correctness and API rate limits. \
                            status_code: {} - url: {} - Response: {}".format(
                        response.status_code, response.url, response.text
                    )
                )
            # jscpd:ignore-end
        # Collecting audit logs after verifying checkpoint conditions
        while last == 0:
            params = {
                "phrase": "",
                "include": self.input_params["events_type"],
                "after": next_hash,
                "before": "",
                "order": "asc",
                "per_page": str(PER_PAGE),
            }
            try:
                response = requests.get(
                    "{}{}".format(api_url, slug),
                    headers=headers,
                    proxies=self.proxies,
                    params=params,
                )
                if response.ok:
                    entries = []
                    for entry in response.json():
                        event_written = write_event(
                            self._logger,
                            event_writer,
                            entry,
                            "github:cloud:audit",
                            self.input_params,
                        )
                        if not event_written:
                            error_flag_for_audit_data = 1
                            break
                        event_counter += 1
                        entries.append(entry)
                    checkpoint_value = {
                        "last_count": len(entries),
                        "last_after": next_hash,
                    }
                    checkpoint_handler(
                        self._logger, self.session_key, checkpoint_value, checkpoint_key
                    )
                    if (
                        "next" not in response.links
                        or not response.links
                        or error_flag_for_audit_data == 1
                    ):
                        self._logger.info(
                            "Successfully ingested {} audit events.".format(
                                event_counter
                            )
                        )
                        break
                    next_hash = parse_qs(urlparse(response.links["next"]["url"]).query)[
                        "after"
                    ][0]
                else:
                    raise RuntimeError(
                        "Could not fetch audit log data. Please check your configuration, \
                            access token scope / correctness and API rate limits. \
                                status_code: {} - url: {} - Response: {}".format(
                            response.status_code, response.url, response.text
                        )
                    )
            except Exception:
                self._logger.error(
                    "Failed to connect. {}".format(traceback.format_exc())
                )
                msg = "Could not connect to GitHub. Check configuration and network settings"
                raise RestError(400, msg)

    def collect_user_data(self, org_name, event_writer):
        error_flag_for_user_data = 0
        api_url = "https://api.github.com"
        slug = "/orgs/{org}/members".replace("{org}", org_name)
        page = 1
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(self.security_token),
        }
        status_forcelist = [429, 502, 503, 504]
        event_counter = 0
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=status_forcelist)
        session.mount("https://", HTTPAdapter(max_retries=retries))
        while True:
            params = {"per_page": str(PER_PAGE), "page": page}
            try:
                response = session.get(
                    "{}{}".format(api_url, slug),
                    headers=headers,
                    proxies=self.proxies,
                    params=params,
                )
                if response.ok and len(response.json()) > 0:
                    new_slug = "/orgs/{org}/memberships/".replace("{org}", org_name)
                    for entry in response.json():
                        new_response = session.get(
                            "{}{}{}".format(api_url, new_slug, entry["login"]),
                            headers=headers,
                            proxies=self.proxies,
                        )
                        if new_response.ok:
                            event_written = write_event(
                                self._logger,
                                event_writer,
                                new_response.json(),
                                "github:cloud:user",
                                self.input_params,
                            )
                        if new_response.status_code == 400:
                            self._logger.error(
                                "ERROR [{}] - GitHub server cannot or will not \
                                    process the request due to Bad Request. {}".format(
                                    new_response.status_code, new_response.json()
                                )
                            )
                            break
                        if new_response.status_code == 403:
                            self._logger.error(
                                "ERROR [{}] - {}".format(
                                    new_response.status_code, new_response.json()
                                )
                            )
                            break
                        if new_response.status_code == 404:
                            self._logger.error(
                                "ERROR [{}] - Requested resource not found {}".format(
                                    new_response.status_code, new_response.json()
                                )
                            )
                            break
                        if not event_written:
                            error_flag_for_user_data = 1
                            break
                        event_counter += 1
                    if (
                        "last" not in response.links
                        or not response.links
                        or error_flag_for_user_data == 1
                    ):
                        self._logger.info(
                            "Successfully ingested {} user events".format(event_counter)
                        )
                        break
                    else:
                        last_page = parse_qs(
                            urlparse(response.links["last"]["url"]).query
                        )["page"][0]
                        page += 1
                        if page == last_page or page == 1:
                            self._logger.info(
                                "Successfully ingested {} user events".format(
                                    event_counter
                                )
                            )
                            break
                elif response.ok:
                    self._logger.error(
                        "Could not fetch user log data. Make sure required scopes are provided to access token."
                    )
                    break
                else:
                    self._logger.error(
                        "ERROR [{}] - {}".format(response.status_code, response.json())
                    )
                    break
            except Exception:
                self._logger.error(
                    "Failed to fetch user data. {}".format(traceback.format_exc())
                )
                raise RuntimeError(
                    "Could not fetch user log data. Please \
                        check your configuration, access token scope / correctness \
                        and API rate limits. status_code: {} - url: {} - Response: {}".format(
                        response.status_code, response.url, response.text
                    )
                )
