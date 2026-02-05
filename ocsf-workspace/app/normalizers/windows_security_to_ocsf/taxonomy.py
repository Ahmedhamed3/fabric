IAM_CATEGORY_UID = 3
AUTHENTICATION_ACTIVITY_UID = 2
AUTHORIZE_SESSION_ACTIVITY_UID = 3

AUTHENTICATION_LOGON_ID = 1
AUTHORIZE_SESSION_ASSIGN_PRIVILEGES_ID = 1

SYSTEM_CATEGORY_UID = 1
PROCESS_ACTIVITY_UID = 7
PROCESS_ACTIVITY_LAUNCH_ID = 1
PROCESS_ACTIVITY_TERMINATE_ID = 2

DEVICE_TYPE_UNKNOWN_ID = 0


def to_class_uid(category_uid: int, class_uid: int) -> int:
    return category_uid * 1000 + class_uid


def to_type_uid(class_uid: int, activity_id: int) -> int:
    return class_uid * 100 + activity_id
