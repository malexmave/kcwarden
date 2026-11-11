from unittest.mock import Mock, patch

import pytest

from kcwarden.auditors.client.client_with_service_account_missing_admin_api_scope import (
    ClientWithServiceAccountMissingAdminApiScope,
)

SUB = "kcwarden.auditors.client.client_with_service_account_missing_admin_api_scope.admin_api_access"


class TestClientWithServiceAccountMissingAdminApiScope:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientWithServiceAccountMissingAdminApiScope(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "service_account, realm_specific, expected",
        [(True, False, True), (False, False, False), (True, True, False)],
    )
    def test_should_consider_client(self, mock_client, auditor, service_account, realm_specific, expected):
        mock_client.has_service_account_enabled.return_value = service_account
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
        mock_client.has_service_account_enabled.return_value = True
        auditor._DB.get_all_clients.return_value = [mock_client]
        with (
            patch(SUB + ".client_has_admin_api_scope", return_value=has_scope),
            patch(SUB + ".get_service_account_admin_api_roles", return_value=roles),
        ):
            results = list(auditor.audit())
        assert len(results) == expected_findings
        if expected_findings:
            assert results[0].to_dict()["additional_details"]["admin_api_roles"] == roles
