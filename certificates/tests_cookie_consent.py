from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from certificates.models import CookieConsent
from django.contrib.sessions.models import Session
from django.conf import settings

User = get_user_model()

class CookieConsentSessionTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='password')

    def test_consent_persistence_after_login(self):
        # 1. Anonymous user visits and accepts cookies
        session = self.client.session
        session.create()
        session_key_before = session.session_key
        session.save() # Ensure it's saved

        # Manually set the cookie in the client to ensure it's sent
        self.client.cookies[settings.SESSION_COOKIE_NAME] = session_key_before

        # Simulate setting consent via view or directly
        CookieConsent.objects.create(
            session_key=session_key_before,
            optional_cookies_accepted=True
        )

        print(f"Consent created for session: {session_key_before}")

        # Verify consent exists
        self.assertTrue(CookieConsent.objects.filter(session_key=session_key_before).exists())

        # 2. User logs in via the VIEW (to trigger the migration logic)
        response = self.client.post('/login/', {
            'username': 'testuser',
            'password': 'password',
            'auth_source': 'local'
        })

        # Check if login was successful (redirects usually)
        self.assertEqual(response.status_code, 302, "Login failed or did not redirect")

        session_key_after = self.client.session.session_key
        print(f"Session key after login: {session_key_after}")

        self.assertNotEqual(session_key_before, session_key_after, "Session key should change after login")

        # 3. Check if consent is still accessible for the new session
        # This simulates what get_cookie_consent does
        has_consent = CookieConsent.objects.filter(session_key=session_key_after).exists()

        # Also check if user is linked
        user_linked = CookieConsent.objects.filter(user=self.user).exists()

        if not has_consent and not user_linked:
            print("FAILURE: Consent NOT found for new session key or user")
        else:
            print("SUCCESS: Consent found for new session key or user")

        # We expect this to pass now
        self.assertTrue(has_consent or user_linked, "Cookie consent should persist after login")
