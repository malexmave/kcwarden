from kcwarden.api.auditor import ClientAuditor
from kcwarden.auditors.subchecks import admin_api_access
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientWithServiceAccountMissingAdminApiScope(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Low
    SHORT_DESCRIPTION = "Service account has Admin API roles, but the client lacks the 'kc-admin-api' scope"
    LONG_DESCRIPTION = (
        admin_api_access.ADMIN_API_SCOPE_DESCRIPTION_INTRO
        + "The service account of this client has roles for the Admin API, but the 'kc-admin-api' scope is neither a "
        "default nor an optional scope of the client." + admin_api_access.ADMIN_API_SCOPE_DESCRIPTION_OUTRO
    )
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
        return (
            super().should_consider_client(client)
            and not client.is_realm_specific_client()
            and client.has_service_account_enabled()
        )

    def audit_client(self, client: Client):
        if admin_api_access.client_has_admin_api_scope(client):
            return
        admin_roles = admin_api_access.get_service_account_admin_api_roles(self._DB, client)
        if admin_roles:
            yield self.generate_finding(
                client,
                additional_details={
                    "admin_api_roles": admin_roles,
                    "default_scopes": client.get_default_client_scopes(),
                    "optional_scopes": client.get_optional_client_scopes(),
                },
            )
