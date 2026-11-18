# Standard library
from datetime import timedelta
import json
import time

# Third-party libraries
import pandas as pd
from colorama import Fore, Style
from openai import RateLimitError, OpenAIError
from azure.identity import DefaultAzureCredential
import requests, urllib.parse


# Local modules
# Local modules
import PROMPT_MANAGEMENT


def get_bearer_token():
    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.securitycenter.microsoft.com/.default")
    return token

def get_mde_workstation_id_from_name(token, device_name):
    """
    Look up a Defender for Endpoint machine ID by device name.
    Works if the user provides either the FQDN or just the short hostname.
    
    Args:
        token: an Azure Identity token (DefaultAzureCredential or similar)
        device_name: short hostname or full FQDN string

    Returns:
        The machine ID (string)

    Raises:
        Exception if no matches are found.
    """
    headers = {"Authorization": f"Bearer {token.token}"}

    # Use 'startswith' so "linux-target-1" will match
    # "linux-target-1.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
    filter_q = urllib.parse.quote(f"startswith(computerDnsName,'{device_name}')")
    url = f"https://api.securitycenter.microsoft.com/api/machines?$filter={filter_q}"

    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()

    machines = resp.json().get("value", [])
    if not machines:
        raise Exception(f"No machine found starting with {device_name}")

    # If multiple machines match, pick the first. 
    # You could add logic here (e.g., choose the most recent 'lastSeen').
    machine_id = machines[0]["id"]
    return machine_id


def quarantine_virtual_machine(token, machine_id, poll_timeout=120, poll_interval=5):
    """
    Submit a full-isolation action for a machine, then poll the platform until the
    action settles.

    Submitting and confirming are different things: the POST returning 200/201 only
    means Defender accepted the request, and the device is not actually cut off until
    the action reports a terminal status.

    Args:
        token: an Azure Identity token
        machine_id: the Defender machine ID (not the hostname)
        poll_timeout: seconds to wait for a terminal status
        poll_interval: seconds between status checks

    Returns:
        (submitted, status) - submitted is False if the request was rejected outright;
        status is the last action status seen, e.g. "Pending", "Completed", "Failed".
    """
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json",
    }

    payload = {
        "Comment": "Isolation via Python Agentic AI using DefaultAzureCredential",
        "IsolationType": "Full",
    }

    resp = requests.post(
        f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
        headers=headers,
        json=payload,
        timeout=30,
    )

    if resp.status_code not in (200, 201):
        print(f"{Fore.RED}Isolation request rejected: HTTP {resp.status_code} {resp.text[:200]}{Style.RESET_ALL}")
        return False, None

    action_id = resp.json().get("id")
    if not action_id:
        return True, None

    deadline = time.time() + poll_timeout
    status = "Pending"
    while time.time() < deadline:
        check = requests.get(
            f"https://api.securitycenter.microsoft.com/api/machineactions/{action_id}",
            headers={"Authorization": f"Bearer {token.token}"},
            timeout=30,
        )
        if check.status_code == 200:
            status = check.json().get("status", status)
            if status != "Pending":
                break
        time.sleep(poll_interval)
    return True, status

def hunt(openai_client, threat_hunt_system_message, threat_hunt_user_message, openai_model):
    """
    Runs the threat hunting flow:
    1. Formats the logs into a string
    2. Selects appropriate system prompt from context
    3. Passes logs + role to model
    4. Parses and returns a raw array
    Handles rate-limit/token overage errors gracefully.
    """

    results = []
    
    messages = [
        threat_hunt_system_message,
        threat_hunt_user_message
    ]

    try:
        response = openai_client.chat.completions.create(
            model=openai_model,
            messages=messages,
            response_format={"type": "json_object"}
        )

        results = json.loads(response.choices[0].message.content)
        return results

    except RateLimitError as e:
        error_msg = str(e)

        # Print dark red warning
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}🚨ERROR: Rate limit or token overage detected!{Style.RESET_ALL}")
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}The input was too large for this model or hit rate limits.")
        print(f"{Style.RESET_ALL}——————————\nRaw Error:\n{error_msg}\n——————————")
        print(f"{Fore.WHITE}Suggestions:")
        print(f"- Use fewer logs or reduce input size.")
        print(f"- Switch to a model with a larger context window.")
        print(f"- Retry later if rate-limited.\n")

        return None  # You can also choose to raise again or exit

    except OpenAIError as e:
        print(f"{Fore.RED}Unexpected OpenAI API error:\n{e}")
        return None

# Extract and parse the function call selected by the LLM.
# This tool call is part of OpenAI's function calling feature, where the model chooses a tool (function)
# from the provided list, and returns the arguments it wants to use to call it.
# In this case, the function selected queries log data from Microsoft Defender via Log Analytics.
#
# Docs: https://platform.openai.com/docs/guides/function-calling
def get_query_context(openai_client, user_message, model):
    
    print(f"{Fore.LIGHTGREEN_EX}\nDeciding log search parameters based on user request...\n")

    system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_TOOL_SELECTION

    response = openai_client.chat.completions.create(
        model=model,
        messages=[system_message, user_message],
        tools=PROMPT_MANAGEMENT.TOOLS,
        tool_choice="required"
    )

    #TODO: Fix this (if there are no returns)
    function_call = response.choices[0].message.tool_calls[0]
    args = json.loads(function_call.function.arguments)

    return args  # or return function_call, args


def query_log_analytics(log_analytics_client, workspace_id, timerange_hours, table_name, device_name, fields, caller, user_principal_name, excluded_callers=None):

    if table_name == "AzureNetworkAnalytics_CL":
        user_query = f'''{table_name}
| where FlowType_s == "MaliciousFlow"
| project {fields}'''
        
    elif table_name == "AzureActivity":
        # Callers in the exclusion list are filtered out: without it the automation's
        # own service principals show up as suspicious control-plane activity on every
        # hunt. Configure AZURE_ACTIVITY_EXCLUDED_CALLERS rather than editing this.
        exclusion = ""
        if excluded_callers:
            quoted = ", ".join(f'"{c}"' for c in excluded_callers)
            exclusion = f"| where Caller !in ({quoted})\n"
        user_query = f'''{table_name}
{exclusion}| where isnotempty(Caller) and Caller startswith "{caller}"
| project {fields}'''
        
    elif table_name == "SigninLogs":
        user_query = f'''{table_name}
| where UserPrincipalName startswith "{user_principal_name}"
| project {fields}'''
        
    else:
        user_query = f'''{table_name}
| where DeviceName startswith "{device_name}"
| project {fields}'''
        
    print(f"{Fore.LIGHTGREEN_EX}Constructed KQL Query:")
    print(f"{Fore.WHITE}{user_query}\n")

    print(f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Workspace ID: '{workspace_id}'...")

    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=user_query,
        timespan=timedelta(hours=timerange_hours)
    )

    if len(response.tables[0].rows) == 0:
        print(f"{Fore.WHITE}No data returned from Log Analytics.")
        return { "records": "", "count": 0 }
    
    # Extract the table
    table = response.tables[0]

    # TODO: Handle if returns 0 events
    record_count = len(response.tables[0].rows)

    # Extract columns and rows using dot notation
    columns = table.columns  # Already a list of strings
    rows = table.rows        # List of row data

    df = pd.DataFrame(rows, columns=columns)
    records = df.to_csv(index=False)

    return { "records": records, "count": record_count }

