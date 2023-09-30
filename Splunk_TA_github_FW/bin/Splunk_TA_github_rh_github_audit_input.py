#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import logging

# isort: off
import import_declare_test  # noqa: F401
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
from splunktaucclib.rest_handler.endpoint import (
    DataInputModel,
    RestModel,
    field,
    validator,
)
from Splunk_TA_github_utils import (
    GetSessionKey,
    delete_checkpoint,
    set_logger,
    ValidateAuditInput,
)

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        "account_type", required=False, encrypted=False, default="orgs", validator=None
    ),
    field.RestField(
        "org_name",
        required=False,
        encrypted=False,
        default=None,
        validator=ValidateAuditInput(),
    ),
    field.RestField(
        "enterprises_name",
        required=False,
        encrypted=False,
        default=None,
        validator=ValidateAuditInput(),
    ),
    field.RestField(
        "events_type", required=True, encrypted=False, default="web", validator=None
    ),
    field.RestField(
        "account", required=True, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "interval",
        required=True,
        encrypted=False,
        default=None,
        validator=validator.AllOf(
            validator.Number(
                max_val=31536000,
                min_val=1,
            ),
            validator.Pattern(
                regex=r"""^\d+$""",
            ),
        ),
    ),
    field.RestField(
        "index",
        required=True,
        encrypted=False,
        default="default",
        validator=validator.String(
            max_len=80,
            min_len=1,
        ),
    ),
    field.RestField("disabled", required=False, validator=None),
    field.RestField(
        "input_type",
        required=False,
        encrypted=False,
        default="GitHub Audit Input",
        validator=None,
    ),
]
model = RestModel(fields, name=None)


endpoint = DataInputModel(
    "github_audit_input",
    model,
)


class GitHubAuditInputHandler(AdminExternalHandler):
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    def handleList(self, confInfo):
        AdminExternalHandler.handleList(self, confInfo)

    def handleEdit(self, confInfo):
        AdminExternalHandler.handleEdit(self, confInfo)

    def handleCreate(self, confInfo):
        AdminExternalHandler.handleCreate(self, confInfo)

    def handleRemove(self, confInfo):
        input_name = self.callerArgs.id
        session_key = GetSessionKey().session_key
        _logger = set_logger(
            session_key,
            "Splunk_TA_github_audit_input_" + input_name,
        )
        delete_checkpoint(
            _logger,
            session_key,
            "github_audit_input://" + input_name,
        )
        _logger.debug(
            "Successfully deleted checkpoint for input: {}".format(input_name)
        )
        AdminExternalHandler.handleRemove(self, confInfo)


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=GitHubAuditInputHandler,
    )
