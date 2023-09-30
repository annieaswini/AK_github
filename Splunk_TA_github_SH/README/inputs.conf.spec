##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

[github_audit_input://<name>]
input_type = <string> Type of input created (Audit or User).
events_type = <string> Type of events to be collected (web, git or all).
account_type = <string> Type of account for which the data would be collected (Organization or Enterprise).
org_name = <string> Name of Organization if Organization is selected from account_type.
enterprises_name = <string> Name of Enterprise if Enterprise is selected account_type.
account = <string> Name of the account that would be used to get data.
interval = <integer> Time in milliseconds for input invocation.
index = <string> Name of index where data will be collected.

[github_user_input://<name>]
input_type = <string> Type of input created (Audit or User).
account = <string> Name of the account that would be used to get data.
org_name = <string> Name of Organization for which user data will be collected.
interval = <integer> Time in milliseconds for input invocation.
index = <string> Name of index where data will be collected.
