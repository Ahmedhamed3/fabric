# OCSF v1.2.0 (based on your schema files)

CATEGORY_UID_SYSTEM = 1
CATEGORY_UID_NETWORK = 4

# From events/system/process.json snippet you pasted:
PROCESS_ACTIVITY_CLASS_UID = 7

# From activity_id enum in process_activity:
PROCESS_ACTIVITY_LAUNCH_ID = 1  # Launch
PROCESS_ACTIVITY_TERMINATE_ID = 2
PROCESS_ACTIVITY_OPEN_ID = 3
PROCESS_ACTIVITY_INJECT_ID = 4

# File System Activity
FILE_SYSTEM_ACTIVITY_CLASS_UID = 1001
FILE_SYSTEM_ACTIVITY_CREATE_ID = 1
FILE_SYSTEM_ACTIVITY_READ_ID = 2
FILE_SYSTEM_ACTIVITY_MODIFY_ID = 3
FILE_SYSTEM_ACTIVITY_DELETE_ID = 4
FILE_SYSTEM_ACTIVITY_OTHER_ID = 99

MODULE_ACTIVITY_CLASS_UID = 5
MODULE_ACTIVITY_LOAD_ID = 1

# HTTP Activity (Network)
HTTP_ACTIVITY_CLASS_UID = 4002
HTTP_ACTIVITY_REQUEST_ID = 1

# In your schema, Codex computed:
# type_uid = class_uid * 100 + activity_id  (for this class)
def calc_type_uid(class_uid: int, activity_id: int) -> int:
    return class_uid * 100 + activity_id

DEFAULT_SEVERITY_ID = 1  # informational/low (safe default for MVP)

DEFAULT_METADATA_PRODUCT = "Microsoft Sysmon"
DEFAULT_METADATA_VERSION = "unknown"  # replace later if you can extract Sysmon version

DEFAULT_DEVICE_TYPE_ID = 0  # unknown (we’ll refine after reading device.json enum)
DEFAULT_FILE_TYPE_ID = 0    # unknown (we’ll refine after reading file.json enum)

# Security Finding (OCSF class UID for findings)
SECURITY_FINDING_CLASS_UID = 2004
SECURITY_FINDING_ACTIVITY_ALERT_ID = 1

# Authentication Activity
AUTHENTICATION_ACTIVITY_CLASS_UID = 3002

# Windows extension registry activity classes
REGISTRY_KEY_ACTIVITY_CLASS_UID = 2001
REGISTRY_VALUE_ACTIVITY_CLASS_UID = 2002
REGISTRY_KEY_ACTIVITY_CREATE_ID = 1
REGISTRY_KEY_ACTIVITY_MODIFY_ID = 3
REGISTRY_KEY_ACTIVITY_DELETE_ID = 4
REGISTRY_KEY_ACTIVITY_RENAME_ID = 5
REGISTRY_VALUE_ACTIVITY_SET_ID = 2
REGISTRY_VALUE_ACTIVITY_MODIFY_ID = 3
REGISTRY_VALUE_ACTIVITY_DELETE_ID = 4
