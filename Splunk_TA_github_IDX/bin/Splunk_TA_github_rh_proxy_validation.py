#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

from splunktaucclib.rest_handler.endpoint.validator import Validator


class ProxyValidation(Validator):
    """
    Validate Proxy details provided
    """

    def __init__(self, *args, **kwargs):
        super(ProxyValidation, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        username_val = data.get("proxy_username")
        password_val = data.get("proxy_password")

        # If password is specified, then username is required
        if password_val and not username_val:
            self.put_msg(
                "Username is required if password is specified", high_priority=True
            )
            return False
        # If username is specified, then password is required
        elif username_val and not password_val:
            self.put_msg(
                "Password is required if username is specified", high_priority=True
            )
            return False

        # If length of username is not satisfying the String length criteria
        if username_val:
            str_len = len(username_val)
            _min_len = 1
            _max_len = 50
            if str_len < _min_len or str_len > _max_len:
                msg = (
                    "String length of username should be between %(min_len)s and %(max_len)s"
                    % {"min_len": _min_len, "max_len": _max_len}
                )
                self.put_msg(msg, high_priority=True)
                return False

        if password_val:
            str_len = len(password_val)
            _min_len = 1
            _max_len = 8192
            if str_len < _min_len or str_len > _max_len:
                msg = (
                    "String length of password should be between %(min_len)s and %(max_len)s"
                    % {"min_len": _min_len, "max_len": _max_len}
                )
                self.put_msg(msg, high_priority=True)
                return False

        return True
