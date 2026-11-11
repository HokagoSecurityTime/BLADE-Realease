from enum import StrEnum


class Label(StrEnum):
    PUBLIC = "public"
    ROLE_REQUIRED = "role_required"
    MEMBERSHIP_REQUIRED = "membership_required"
    TENANT_MATCH = "tenant_match"
    OWNER_MATCH = "owner_match"
    OWNER_OR_ADMIN = "owner_or_admin"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"
