from unittest.mock import Mock, patch

import pytest

from kcwarden.auditors.client.client_with_scope_mapped_admin_roles_missing_admin_api_scope import (
    ClientWithScopeMappedAdminRolesMissingAdminApiScope,
)

SUB = "kcwarden.auditors.client.client_with_scope_mapped_admin_roles_missing_admin_api_scope.admin_api_access"


class TestClientWithScopeMappedAdminRolesMissingAdminApiScope:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientWithScopeMappedAdminRolesMissingAdminApiScope(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "full_scope, realm_specific, expected",
        [(False, False, True), (True, False, False), (False, True, False)],
    )
    def test_should_consider_client(self, mock_client, auditor, full_scope, realm_specific, expected):
        mock_client.has_full_scope_allowed.return_value = full_scope
        mock_client.is_realm_specific_client.return_value = realm_specific
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "has_scope, roles, expected_findings",
        [
            (False, {"realm-management": ["view-users"]}, 1),
            (True, {"realm-management": ["view-users"]}, 0),
            (False, {}, 0),
        ],
    )
    def test_audit(self, mock_client, auditor, has_scope, roles, expected_findings):
        auditor._DB.get_all_clients.return_value = [mock_client]
        with (
            patch(SUB + ".client_has_admin_api_scope", return_value=has_scope),
            patch(SUB + ".get_scope_mapped_admin_api_roles", return_value=roles),
        ):
            results = list(auditor.audit())
        assert len(results) == expected_findings
        if expected_findings:
            assert results[0].to_dict()["additional_details"]["admin_api_roles"] == roles
