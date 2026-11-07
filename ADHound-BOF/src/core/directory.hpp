#pragma once
#include "../../../common/ldap/directory.hpp"
struct ah_session_info { char *sid, *name, *computer_sid; uint32_t time, idle; SID_NAME_USE usage; ah_session_info *next; };
struct ah_local_group_info { char *name, *sid, *raw_sid; const char *failure_reason; ah_session_info *members; ah_local_group_info *next; bool collected; };
struct ah_gpo_change { ah_session_info *local_admins, *remote_desktop_users, *dcom_users, *psremote_users, *affected_computers; };
struct ah_gpo_computer;
struct ah_object {
    const wchar_t *type;
    char *dn, *id, *raw_sid;
    const char *kind;
    ah_attr *attributes;
    ah_object *next, *parent, *children, *sibling, *registry_host;
    bool registry_host_resolved;
    bool exported, stealth_targeted, auxiliary_only, explicit_target, consumer_failed;
    ah_session_info *sessions, *privileged_sessions, *registry_sessions, *ca_registry;
    ah_local_group_info *local_groups, *user_rights;
    ah_gpo_change *gpo_changes;
    ah_gpo_computer *gpo_computers;
    ah_value *client_allowed_servers, *ca_security, *enrollment_agent_rights;
    char *vulnerable_netlogon, *azure_vm_id, *machine_sid;
    const char *sessions_failure_reason, *privileged_failure_reason, *registry_failure_reason;
    bool hostavailability_checked, host_connectable;
    const char *host_failure;
    bool ntlm_registry_requested, ntlm_registry_collected;
    const char *ntlm_registry_failure;
    bool dc_registry_requested, cert_mapping_collected, strong_binding_collected, vulnerable_netlogon_collected;
    bool canonical_api_name, synthesized_dns_name;
    bool azure_registry_requested, azure_registry_collected;
    const char *azure_registry_failure;
    const char *cert_mapping_failure, *strong_binding_failure, *vulnerable_netlogon_failure;
    bool ca_registry_requested, ca_security_collected, enrollment_agent_collected, san_collected, role_separation_collected;
    const char *ca_security_failure, *enrollment_agent_failure, *san_failure, *role_separation_failure;
    bool sessions_collected, privileged_collected, registry_collected;
    bool smb_signing_collected, smb_signing, webclient_collected, webclient_running, webclient_requested;
    const char *webclient_failure;
    bool ntlm_require_signing_valid, client_allowed_servers_valid;
    uint32_t ntlm_require_signing;
    bool ldap_available, ldaps_available, ldap_signing_valid, ldap_signing;
    bool ldaps_cbt_valid, ldaps_cbt_disabled;
    const char *ldaps_cbt_failure, *ldap_signing_failure;
    bool channel_binding_valid;
    uint32_t channel_binding;
    bool san_valid, san_enabled, role_separation_valid, role_separation_enabled;
    bool cert_mapping_valid, strong_binding_valid, vulnerable_netlogon_valid;
    bool lm_level_valid, min_client_valid, min_server_valid, restrict_sending_valid, restrict_receiving_valid;
    bool use_machine_id_valid, enable_signing_valid;
    uint32_t cert_mapping, strong_binding, lm_level, min_client, min_server;
    uint32_t restrict_sending, restrict_receiving, use_machine_id, enable_signing;
    ah_attr *attr(const char *name) const {
        for (ah_attr *a = attributes; a; a = a->next) if (ah_eq(a->name, name)) return a;
        return nullptr;
    }
    ah_value *values(const char *name) const { ah_attr *a = attr(name); return a ? a->values : nullptr; }
    const char *text(const char *name, const char *fallback = "") const { ah_value *v = values(name); return v ? v->data : fallback; }
};

struct ah_call_status { const char *computer, *task, *status, *object_id; ah_call_status *next; };
struct ah_directory_state { ah_call_status *call_status = nullptr, *call_status_tail = nullptr; };


#include "../../../common/ldap/directory_store.hpp"
#include "binary_identifiers.hpp"
