from enum import Enum


class EvidenceCategory(str, Enum):
    IDENTITY_AUTHENTICATION = "Identity & Authentication Evidence"
    PROCESS_EXECUTION = "Process & Execution Evidence"
    FILE_ARTIFACT = "File & Artifact Evidence"
    NETWORK_ACTIVITY = "Network Activity Evidence"
    SECURITY_DETECTION = "Security Detection Evidence"
    SYSTEM_CONFIGURATION_PERSISTENCE = "System Configuration & Persistence Evidence"
    APPLICATION_ACCESS = "Application & Access Evidence"
    CLOUD_INFRASTRUCTURE = "Cloud & Infrastructure Evidence"
