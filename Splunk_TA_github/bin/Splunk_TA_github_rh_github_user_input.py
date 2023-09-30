#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import logging

# isort: off
import import_declare_test  # noqa: F401
from Splunk_TA_github_utils import ValidateUserInput
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
from splunktaucclib.rest_handler.endpoint import (
    DataInputModel,
    RestModel,
    field,
    validator,
)

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        "org_name",
        required=True,
        encrypted=False,
        default=None,
        validator=ValidateUserInput(),
    ),
    field.RestField(
        "interval",
        required=True,
        encrypted=False,
        default=86400,
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
        "account", required=True, encrypted=False, default=None, validator=None
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
        default="GitHub User Input",
        validator=None,
    ),
]
model = RestModel(fields, name=None)


endpoint = DataInputModel(
    "github_user_input",
    model,
)


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=AdminExternalHandler,
    )
