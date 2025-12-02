"""
Custom authentication backends for SSL Manager.

This module provides two authentication backends:
1. SourceAwareLDAPBackend - Authenticates against LDAP/Active Directory
2. SourceAwareModelBackend - Authenticates against local Django database

Both backends check for an 'auth_source' parameter to determine which
authentication method should be used.
"""

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.conf import settings
from ldap3 import Server, Connection, ALL, SIMPLE
import logging

logger = logging.getLogger(__name__)

User = get_user_model()


class SourceAwareLDAPBackend(ModelBackend):
    """
    LDAP authentication backend that only authenticates when auth_source='ldap'.

    Uses ldap3 directly to avoid dependency issues with django-python3-ldap/pyasn1.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        auth_source = kwargs.get('auth_source', None)

        # Only proceed if explicitly requested to use LDAP
        if auth_source != 'ldap':
            return None

        # CRITICAL: Check if user exists in Django database first
        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None

        # LDAP Authentication Logic
        ldap_url = getattr(settings, 'LDAP_AUTH_URL', 'ldap://localhost:389')
        search_base = getattr(settings, 'LDAP_AUTH_SEARCH_BASE', '')

        try:
            # 1. Connect to LDAP
            server = Server(ldap_url, get_info=ALL)

            # 2. Find User DN
            bind_user = getattr(settings, 'LDAP_AUTH_CONNECTION_USERNAME', None)
            bind_password = getattr(settings, 'LDAP_AUTH_CONNECTION_PASSWORD', None)
            user_dn = None

            if bind_user and bind_password:
                # Bind as admin to search
                conn = Connection(server, bind_user, bind_password, auto_bind=True)
                search_filter = f'(uid={username})' # Assuming uid is the username attribute
                conn.search(search_base, search_filter, attributes=['entryDN'])

                if conn.entries:
                    user_dn = conn.entries[0].entry_dn

            if not user_dn:
                # Fallback: Construct DN if search failed or no bind creds
                # This assumes a standard structure: uid=username,search_base
                user_dn = f"uid={username},{search_base}"

            # 3. Bind as User to Authenticate
            user_conn = Connection(server, user_dn, password, auto_bind=True)

            # If we get here, authentication was successful
            if request:
                request.session['auth_source'] = 'ldap'

            return user

        except Exception as e:
            logger.error(f"LDAP auth failed for {username}: {e}")
            return None


class SourceAwareModelBackend(ModelBackend):
    """
    Local Django authentication backend that only authenticates when auth_source='local'.

    This backend extends Django's ModelBackend to add source awareness.
    It will only attempt local authentication if the 'auth_source' kwarg is set to 'local'
    or if no auth_source is specified (default behavior).
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticate against local Django database only if auth_source is 'local' or not specified.

        Args:
            request: The HTTP request object
            username: The username to authenticate
            password: The password to authenticate
            **kwargs: Additional keyword arguments, expecting 'auth_source'

        Returns:
            User object if authentication succeeds, None otherwise
        """
        auth_source = kwargs.get('auth_source', 'local')

        # Only proceed if explicitly local or no source specified
        if auth_source != 'local':
            return None

        # Call parent Model authentication
        authenticated_user = super().authenticate(request, username=username, password=password)

        # If local authentication succeeded, store auth source in session
        if authenticated_user and request:
            request.session['auth_source'] = 'local'

        return authenticated_user
