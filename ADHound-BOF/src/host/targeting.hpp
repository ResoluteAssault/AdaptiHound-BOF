#pragma once

static int ah_stealth_methods(int methods) {
    bool local_groups = (methods & AH_LOCAL_GROUPS) != 0;
    methods &= ~(AH_LOGGEDON | AH_LOCAL_GROUPS | AH_CA_REGISTRY | AH_DC_REGISTRY | AH_NTLM_REGISTRY | AH_AZURE_REGISTRY);
    if (local_groups) methods |= AH_GPO_LOCAL_GROUP;
    return methods;
}
