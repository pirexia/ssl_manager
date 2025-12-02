"""
LDAP synchronization functions for django-python3-ldap.

These functions customize how LDAP users are synchronized with the local Django database.
The key customization is preventing auto-creation of new users - users must be pre-registered.
"""

from django.contrib.auth import get_user_model

User = get_user_model()


def clean_user_data(user_data):
    """
    Clean and transform user data from LDAP before syncing.

    Args:
        user_data: Dictionary of user data from LDAP

    Returns:
        Dictionary of cleaned user data
    """
    return user_data


def sync_user_relations(user, ldap_attributes):
    """
    Sync user relations (groups, permissions) from LDAP.

    This function is called after user authentication to sync additional
    user attributes that aren't stored in the User model directly.

    Args:
        user: The Django User object
        ldap_attributes: Dictionary of LDAP attributes
    """
    # We don't sync groups/relations automatically
    # This can be customized to sync LDAP groups to Django groups
    pass


def format_search_filters(ldap_fields):
    """
    Format LDAP search filters.

    Args:
        ldap_fields: Dictionary of LDAP field mappings

    Returns:
        String containing the LDAP search filter
    """
    # Standard search filter format
    search_filters = []
    for field, value in ldap_fields.items():
        search_filters.append("({field}={value})".format(field=field, value=value))

    return "(&{filters})".format(filters="".join(search_filters))


def format_username(ldap_username):
    """
    Format the username from LDAP.

    This function can be used to transform usernames from LDAP before
    looking them up in the Django database.

    Args:
        ldap_username: The username from LDAP

    Returns:
        Formatted username string
    """
    # Return username as-is (case-sensitive)
    # Can be modified to lowercase: return ldap_username.lower()
    return ldap_username
