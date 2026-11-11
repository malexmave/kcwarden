from kcwarden.api.auditor import ClientAuditor
from kcwarden.auditors.subchecks import admin_api_access
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.custom_types.result import Severity


class ClientWithScopeMappedAdminRolesMissingAdminApiScope(ClientAuditor):
    DEFAULT_SEVERITY = Severity.Info
    SHORT_DESCRIPTION = "Client has Admin API roles in its scope mappings, but lacks the 'kc-admin-api' scope"
    LONG_DESCRIPTION = (
        admin_api_access.ADMIN_API_SCOPE_DESCRIPTION_INTRO
        + "This client has roles for the Admin API in its explicit scope mappings (on the client or its client "
        "scopes), so tokens issued for user logins may be used for Admin API access, but the 'kc-admin-api' scope is "
        "neither a default nor an optional scope of the client. Note that this only shows that the client may carry "
        "such roles, not that any user actually has them or that the client is used for Admin API access, so this "
        "finding may be a false positive. Clients with 'full scope allowed' are not checked."
        + admin_api_access.ADMIN_API_SCOPE_DESCRIPTION_OUTRO
    )
    REFERENCE = ""

    def should_consider_client(self, client: Client) -> bool:
        return (
            super().should_consider_client(client)
            and not client.is_realm_specific_client()
            and not client.has_full_scope_allowed()
        )

    def audit_client(self, client: Client):
        if admin_api_access.client_has_admin_api_scope(client):
            return
        admin_roles = admin_api_access.get_scope_mapped_admin_api_roles(self._DB, client)
        if admin_roles:
            yield self.generate_finding(
                client,
                additional_details={
                    "admin_api_roles": admin_roles,
                    "default_scopes": client.get_default_client_scopes(),
                    "optional_scopes": client.get_optional_client_scopes(),
                },
            )
