"""Copy this file to _keys.py and fill in your own values.

_keys.py is git-ignored, so the real values never get committed. Every setting
here also works as an environment variable of the same name, which is the better
option if you would rather not have a secrets file on disk at all.
"""

# https://platform.openai.com/settings/organization/api-keys
OPENAI_API_KEY = "YOUR-KEY-HERE"

# The Log Analytics workspace GUID that backs your Sentinel workspace - the
# workspace ID, not the workspace name.
LOG_ANALYTICS_WORKSPACE_ID = "WORKSPACE-ID-HERE"

# Optional. Callers to keep out of AzureActivity results so your own automation
# service principals do not read as suspicious control-plane activity.
# As an environment variable, pass a comma-separated string instead.
AZURE_ACTIVITY_EXCLUDED_CALLERS = []
