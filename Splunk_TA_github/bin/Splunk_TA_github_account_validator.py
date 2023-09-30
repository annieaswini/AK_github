#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

"""
This module validates account being saved by the user
"""

import json  # noqa: F401
import traceback  # noqa: F401

import requests

# isort: off
import import_declare_test  # noqa: F401
import splunk.admin as admin  # noqa: F401
from Splunk_TA_github_utils import get_proxy_settings
from solnlib import log
from splunktaucclib.rest_handler.error import RestError


_LOGGER = log.Logs().get_logger("Splunk_TA_github_account_validator")


def account_validation(security_token, session_key):
    """
    This method verifies the credentials by making an API call
    """

    try:

        proxy_settings = get_proxy_settings(_LOGGER, session_key)

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(security_token),
        }
        api_url = "https://api.github.com/user"

        resp = requests.get(url=api_url, proxies=proxy_settings, headers=headers)

    except Exception:
        _LOGGER.error("Failed to connect. {}".format(traceback.format_exc()))
        msg = "Could not connect to GitHub. Check configuration and network settings"
        raise RestError(400, msg)

    if resp.status_code in (200, 201):
        _LOGGER.info("Account validated successfully")
        return True
    if resp.status_code == 400:
        _LOGGER.error(
            "ERROR [{}] - GitHub server cannot or will not process the request due to Bad Request. {}".format(
                resp.status_code, resp.json()
            )
        )
        raise RestError(
            resp.status_code, "GitHub server cannot process the request. Bad Request."
        )
    if resp.status_code == 401:
        _LOGGER.error(
            "ERROR [{}] - The request cannot be processed due to bad credentials. {}".format(
                resp.status_code, resp.json()
            )
        )
        raise RestError(
            resp.status_code,
            "Incorrect personal access token",
        )
    if resp.status_code == 403:
        _LOGGER.error("ERROR [{}] - {}".format(resp.status_code, resp.json()))
        raise RestError(
            resp.status_code,
            resp.json()["message"],
        )
    else:
        _LOGGER.error("Error [{}] - {}".format(resp.status_code, resp.json()))
        raise RestError(
            resp.status_code,
            "Could not connect to GitHub",
        )
