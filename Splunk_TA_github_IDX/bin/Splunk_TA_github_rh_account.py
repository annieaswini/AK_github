#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

# isort: off
import import_declare_test  # noqa: F401
import logging

from Splunk_TA_github_account_validator import account_validation
from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    SingleModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        "security_token",
        required=True,
        encrypted=True,
        default=None,
        validator=validator.String(
            max_len=8192,
            min_len=1,
        ),
    )
]
model = RestModel(fields, name=None)


endpoint = SingleModel("splunk_ta_github_account", model, config_name="account")


class GitHubAuditAccountHandler(AdminExternalHandler):
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    def handleList(self, confInfo):
        AdminExternalHandler.handleList(self, confInfo)

    def handleEdit(self, confInfo):
        account_validation(
            self.payload.get("security_token"),
            self.getSessionKey(),
        )
        AdminExternalHandler.handleEdit(self, confInfo)

    def handleCreate(self, confInfo):
        account_validation(
            self.payload.get("security_token"),
            self.getSessionKey(),
        )
        AdminExternalHandler.handleCreate(self, confInfo)

    def handleRemove(self, confInfo):
        AdminExternalHandler.handleRemove(self, confInfo)


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=GitHubAuditAccountHandler,
    )
