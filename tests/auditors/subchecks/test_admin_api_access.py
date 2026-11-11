from unittest.mock import Mock, patch

import pytest

from kcwarden.auditors.subchecks import admin_api_access as sub

HELPER = "kcwarden.auditors.subchecks.admin_api_access.helper"


@pytest.mark.parametrize(
    "default, optional, expected",
    [([], [], False), (["kc-admin-api"], [], True), ([], ["kc-admin-api"], True), (["profile"], ["email"], False)],
)
def test_client_has_admin_api_scope(mock_client, default, optional, expected):
    mock_client.get_default_client_scopes.return_value = default
    mock_client.get_optional_client_scopes.return_value = optional
    assert sub.client_has_admin_api_scope(mock_client) == expected


@pytest.mark.parametrize(
    "client_name, realm_name, expected",
    [
        ("realm-management", "test", True),
        ("realm-management", "master", True),
        ("other-realm", "master", True),
        ("other-realm", "test", False),
        ("some-client", "master", False),
    ],
)
def test_is_admin_api_client_name(client_name, realm_name, expected):
    assert sub.is_admin_api_client_name(client_name, realm_name) == expected


def test_filter_admin_api_roles():
    roles = {"realm": ["x"], "client": {"realm-management": ["b", "a"], "other": ["x"], "empty": []}}
    assert sub.filter_admin_api_roles(roles, "test") == {"realm-management": ["a", "b"]}


def test_service_account_roles(mock_client):
    mock_client.has_service_account_enabled.return_value = True
    mock_client.get_service_account_name.return_value = "service-account-x"
    mock_client.get_realm.return_value.get_name.return_value = "test"
    roles = {"realm": [], "client": {"realm-management": ["view-users"], "other": ["x"]}}
    with patch(HELPER + ".get_effective_roles_for_service_account", return_value=roles):
        assert sub.get_service_account_admin_api_roles(Mock(), mock_client) == {"realm-management": ["view-users"]}


def test_service_account_roles_without_service_account(mock_client):
    mock_client.has_service_account_enabled.return_value = False
    assert sub.get_service_account_admin_api_roles(Mock(), mock_client) == {}


def test_service_account_roles_missing_service_account(mock_client):
    mock_client.has_service_account_enabled.return_value = True
    db = Mock()
    db.get_service_account.side_effect = KeyError("x")
    assert sub.get_service_account_admin_api_roles(db, mock_client) == {}


def _scope_mapping_setup(mock_client, full_scope=False):
    mock_client.has_full_scope_allowed.return_value = full_scope
    mock_client.get_realm.return_value.get_name.return_value = "test"
    mock_client.get_default_client_scopes.return_value = ["some-scope"]
    mock_client.get_directly_assigned_client_roles.return_value = {"realm-management": ["manage-users"]}
    scope = Mock()
    scope.get_realm_roles.return_value = []
    scope.get_client_roles.return_value = {"realm-management": ["view-users"]}
    db = Mock()
    db.get_scope.return_value = scope
    return db


def test_scope_mapped_roles(mock_client):
    db = _scope_mapping_setup(mock_client)
    with patch(HELPER + ".get_effective_roles_for_role_names", side_effect=lambda d, r, c: {"realm": r, "client": c}):
        assert sub.get_scope_mapped_admin_api_roles(db, mock_client) == {
            "realm-management": ["manage-users", "view-users"]
        }


def test_scope_mapped_roles_ignore_full_scope(mock_client):
    db = _scope_mapping_setup(mock_client, full_scope=True)
    assert sub.get_scope_mapped_admin_api_roles(db, mock_client) == {}


def test_scope_mapped_roles_skip_unknown_scope(mock_client):
    db = _scope_mapping_setup(mock_client)
    db.get_scope.side_effect = KeyError("x")
    mock_client.get_directly_assigned_client_roles.return_value = {}
    assert sub.get_scope_mapped_admin_api_roles(db, mock_client) == {}
