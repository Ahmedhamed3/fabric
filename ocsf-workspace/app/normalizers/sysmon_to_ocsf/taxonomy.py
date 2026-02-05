SYSTEM_CATEGORY_UID = 1
NETWORK_CATEGORY_UID = 4

PROCESS_ACTIVITY_UID = 7
FILE_ACTIVITY_UID = 1
NETWORK_ACTIVITY_UID = 1
DNS_ACTIVITY_UID = 3

PROCESS_ACTIVITY_LAUNCH_ID = 1
PROCESS_ACTIVITY_TERMINATE_ID = 2
NETWORK_ACTIVITY_OPEN_ID = 1
DNS_ACTIVITY_QUERY_ID = 1
FILE_ACTIVITY_CREATE_ID = 1

DEVICE_TYPE_UNKNOWN_ID = 0
FILE_TYPE_UNKNOWN_ID = 0
NETWORK_DIRECTION_UNKNOWN_ID = 0


def to_class_uid(category_uid: int, class_uid: int) -> int:
    return category_uid * 1000 + class_uid


def to_type_uid(class_uid: int, activity_id: int) -> int:
    return class_uid * 100 + activity_id
