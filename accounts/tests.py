"""
Topic 13 — Testing for user-service.
13.1 Unit tests — registration validation logic
13.2 API tests  — register, login, me endpoints
13.3 Integration tests — API + DB together
"""

from django.test import TestCase
from django.contrib.auth.models import User, Group
from rest_framework.test import APIClient
from rest_framework import status


# ── helpers ───────────────────────────────────────────────────

def get_token(client, username, password='Pass1234'):
    resp = client.post(
        '/api/v1/auth/token/',
        {'username': username, 'password': password},
        format='json',
    )
    return resp.data.get('access', '')


# ─────────────────────────────────────────────────────────────
# 13.1 Unit Tests
# ─────────────────────────────────────────────────────────────

class AccountServiceUnitTest(TestCase):
    """Unit tests for registration validation logic."""

    def setUp(self):
        from accounts.services.account_service import AccountService
        self.svc = AccountService

    def test_valid_registration_returns_none(self):
        error = self.svc.validate_registration(
            'testuser', 'test@test.com', 'Pass1234', 'Pass1234'
        )
        self.assertIsNone(error)

    def test_password_too_short(self):
        error = self.svc.validate_registration(
            'testuser', 'test@test.com', 'short', 'short'
        )
        self.assertIsNotNone(error)

    def test_password_no_uppercase(self):
        error = self.svc.validate_registration(
            'testuser', 'test@test.com', 'pass1234', 'pass1234'
        )
        self.assertIsNotNone(error)

    def test_password_no_number(self):
        error = self.svc.validate_registration(
            'testuser', 'test@test.com', 'Password', 'Password'
        )
        self.assertIsNotNone(error)

    def test_passwords_do_not_match(self):
        error = self.svc.validate_registration(
            'testuser', 'test@test.com', 'Pass1234', 'Pass5678'
        )
        self.assertIsNotNone(error)

    def test_duplicate_username(self):
        User.objects.create_user('existinguser', password='Pass1234')
        error = self.svc.validate_registration(
            'existinguser', 'new@test.com', 'Pass1234', 'Pass1234'
        )
        self.assertIsNotNone(error)

    def test_empty_username_is_rejected(self):
        """Username cannot be blank."""
        error = self.svc.validate_registration(
            '', 'test@test.com', 'Pass1234', 'Pass1234'
        )
        self.assertIsNotNone(error)

    def test_username_with_spaces_is_rejected(self):
        """Username cannot contain spaces."""
        error = self.svc.validate_registration(
            'test user', 'test@test.com', 'Pass1234', 'Pass1234'
        )
        self.assertIsNotNone(error)

    def test_username_too_short_is_rejected(self):
        """Username must be at least 3 characters."""
        error = self.svc.validate_registration(
            'ab', 'test@test.com', 'Pass1234', 'Pass1234'
        )
        self.assertIsNotNone(error)

    def test_username_case_insensitive_duplicate(self):
        """'Admin' and 'admin' should be treated as duplicates."""
        User.objects.create_user('Admin', password='Pass1234')
        error = self.svc.validate_registration(
            'admin', 'other@test.com', 'Pass1234', 'Pass1234'
        )
        self.assertIsNotNone(error)

    # --- Email validation ---

    def test_empty_email_is_rejected(self):
        """Email field cannot be blank."""
        error = self.svc.validate_registration(
            'testuser', '', 'Pass1234', 'Pass1234'
        )
        self.assertIsNotNone(error)

    def test_invalid_email_format_is_rejected(self):
        """Email must contain @ and a domain."""
        error = self.svc.validate_registration(
            'testuser', 'notanemail', 'Pass1234', 'Pass1234'
        )
        self.assertIsNotNone(error)

    def test_email_missing_domain_is_rejected(self):
        """Email like user@ should be invalid."""
        error = self.svc.validate_registration(
            'testuser', 'user@', 'Pass1234', 'Pass1234'
        )
        self.assertIsNotNone(error)

    def test_duplicate_email_is_rejected(self):
        """Two accounts cannot share the same email."""
        User.objects.create_user(
            'existinguser', email='taken@test.com', password='Pass1234'
        )
        error = self.svc.validate_registration(
            'newuser', 'taken@test.com', 'Pass1234', 'Pass1234'
        )
        self.assertIsNotNone(error)

    # --- Password edge cases ---

    def test_empty_password_is_rejected(self):
        """Password cannot be blank."""
        error = self.svc.validate_registration(
            'testuser', 'test@test.com', '', ''
        )
        self.assertIsNotNone(error)

    def test_password_all_numbers_is_rejected(self):
        """Password like '12345678' has no letter or uppercase."""
        error = self.svc.validate_registration(
            'testuser', 'test@test.com', '12345678', '12345678'
        )
        self.assertIsNotNone(error)

    def test_password_all_uppercase_no_number_rejected(self):
        """Password like 'PASSWORD' has no digit."""
        error = self.svc.validate_registration(
            'testuser', 'test@test.com', 'PASSWORD', 'PASSWORD'
        )
        self.assertIsNotNone(error)

    def test_password_exactly_minimum_length_accepted(self):
        """Password of exactly 8 characters meeting all rules is valid."""
        error = self.svc.validate_registration(
            'testuser', 'test@test.com', 'Pass123!', 'Pass123!'
        )
        self.assertIsNone(error)

    def test_password_with_special_characters_accepted(self):
        """Special characters in password should be allowed."""
        error = self.svc.validate_registration(
            'testuser', 'test@test.com', 'P@ssw0rd!', 'P@ssw0rd!'
        )
        self.assertIsNone(error)

    def test_password_whitespace_only_is_rejected(self):
        """Password made of only spaces should be invalid."""
        error = self.svc.validate_registration(
            'testuser', 'test@test.com', '        ', '        '
        )
        self.assertIsNotNone(error)


# ─────────────────────────────────────────────────────────────
# 13.2 API Tests
# ─────────────────────────────────────────────────────────────

class UserAPITest(TestCase):
    """API tests for user endpoints."""

    def setUp(self):
        self.client = APIClient()
        g, _ = Group.objects.get_or_create(name='Employee')
        self.user = User.objects.create_user(
            'emp1', email='emp1@test.com', password='Pass1234'
        )
        self.user.groups.add(g)

    def test_get_token_success(self):
        resp = self.client.post(
            '/api/v1/auth/token/',
            {'username': 'emp1', 'password': 'Pass1234'},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn('access', resp.data)

    def test_get_token_wrong_password(self):
        resp = self.client.post(
            '/api/v1/auth/token/',
            {'username': 'emp1', 'password': 'wrongpass'},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_me_endpoint_authenticated(self):
        token = get_token(self.client, 'emp1')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        resp = self.client.get('/api/v1/users/me/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data['username'], 'emp1')

    def test_me_endpoint_unauthenticated(self):
        resp = self.client.get('/api/v1/users/me/')
        self.assertIn(resp.status_code, [401, 403])

    def test_register_api_success(self):
        resp = self.client.post(
            '/api/v1/users/register/',
            {
                'username':   'newuser',
                'email':      'new@test.com',
                'first_name': 'New',
                'last_name':  'User',
                'password1':  'Pass1234',
                'password2':  'Pass1234',
            },
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

    def test_register_api_duplicate_username(self):
        resp = self.client.post(
            '/api/v1/users/register/',
            {
                'username':   'emp1',
                'email':      'other@test.com',
                'first_name': 'Other',
                'last_name':  'User',
                'password1':  'Pass1234',
                'password2':  'Pass1234',
            },
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


# ─────────────────────────────────────────────────────────────
# 13.3 Integration Tests
# ─────────────────────────────────────────────────────────────

class UserIntegrationTest(TestCase):
    """Integration: API call → DB record verified."""

    def setUp(self):
        self.client = APIClient()

    def test_register_creates_user_in_db(self):
        resp = self.client.post(
            '/api/v1/users/register/',
            {
                'username':   'intuser',
                'email':      'int@test.com',
                'first_name': 'Int',
                'last_name':  'User',
                'password1':  'Pass1234',
                'password2':  'Pass1234',
            },
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username='intuser').exists())

    def test_register_assigns_employee_group(self):
        self.client.post(
            '/api/v1/users/register/',
            {
                'username':   'groupuser',
                'email':      'group@test.com',
                'first_name': 'Group',
                'last_name':  'User',
                'password1':  'Pass1234',
                'password2':  'Pass1234',
            },
            format='json',
        )
        user = User.objects.get(username='groupuser')
        self.assertTrue(user.groups.filter(name='Employee').exists())

    def test_login_returns_jwt_token(self):
        User.objects.create_user('loginuser', password='Pass1234')
        resp = self.client.post(
            '/api/v1/auth/token/',
            {'username': 'loginuser', 'password': 'Pass1234'},
            format='json',
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn('access', resp.data)
        self.assertIn('refresh', resp.data)