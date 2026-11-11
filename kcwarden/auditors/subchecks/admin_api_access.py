from kcwarden.custom_types.database import Database
from kcwarden.custom_types.keycloak_object import Client
from kcwarden.database import helper

ADMIN_API_SCOPE = "kc-admin-api"
REALM_MANAGEMENT_CLIENT = "realm-management"

ADMIN_API_SCOPE_DESCRIPTION_INTRO = (
    "Newer Keycloak versions (26.6.8 and later; the exact version may differ for backports in downstream "
    "distributions such as RHBK) require clients that access the Admin API to have the 'kc-admin-api' client "
    "scope assigned. The migration to this version assigns the scope automatically to 'admin-cli' and "
    "'security-admin-console', but custom clients must be updated manually. "
)
ADMIN_API_SCOPE_DESCRIPTION_OUTRO = (
    " Admin API calls using this client will stop working once Keycloak is upgraded to a version that enforces the "
    "scope. Assign the scope to the client (as a default scope, or as an optional scope that is explicitly requested)."
)


def client_has_admin_api_scope(client: Client) -> bool:
    return ADMIN_API_SCOPE in client.get_default_client_scopes() + client.get_optional_client_scopes()


def is_admin_api_client_name(client_name: str, realm_name: str) -> bool:
    # In regular realms, Admin API permissions are roles of the "realm-management" client.
    # In the master realm, the permissions for other realms are roles of the "<realm>-realm" clients.
    return client_name == REALM_MANAGEMENT_CLIENT or (realm_name == "master" and client_name.endswith("-realm"))


def filter_admin_api_roles(effective_roles: dict, realm_name: str) -> dict[str, list[str]]:
    """Reduces an effective role dict to the Admin API client roles, keyed by role client."""
    return {
        role_client: sorted(roles)
        for role_client, roles in effective_roles["client"].items()
        if roles and is_admin_api_client_name(role_client, realm_name)
    }


def get_service_account_admin_api_roles(db: Database, client: Client) -> dict[str, list[str]]:
    if not client.has_service_account_enabled():
        return {}
    try:
        service_account = db.get_service_account(client.get_service_account_name())
    except KeyError:
        return {}
    roles = helper.get_effective_roles_for_service_account(db, service_account)
    return filter_admin_api_roles(roles, client.get_realm().get_name())


def get_scope_mapped_admin_api_roles(db: Database, client: Client) -> dict[str, list[str]]:
    """
    Admin API roles that the client may put into tokens for user logins through explicit scope mappings, either
    directly on the client or through its client scopes. Clients with 'full scope allowed' are not considered.
    """
    if client.has_full_scope_allowed():
        return {}
    realm_roles = list(client.get_directly_assigned_realm_roles())
    client_roles = {k: list(v) for k, v in client.get_directly_assigned_client_roles().items()}
    for scope_name in client.get_default_client_scopes() + client.get_optional_client_scopes():
        try:
            scope = db.get_scope(scope_name)
        except KeyError:
            continue
        realm_roles.extend(scope.get_realm_roles())
        for role_client, role_names in scope.get_client_roles().items():
            client_roles.setdefault(role_client, []).extend(role_names)
    return filter_admin_api_roles(
        helper.get_effective_roles_for_role_names(db, realm_roles, client_roles), client.get_realm().get_name()
    )
