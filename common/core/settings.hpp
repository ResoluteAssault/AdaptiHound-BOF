#pragma once

static const long ah_ldap_query_timeout_seconds = 120;
static LDAPControlW *ah_ldap_scope_control = nullptr;
static bool ah_pretty_print = false;
static bool ah_no_zip = false;
static bool ah_random_filenames = false;
static const char *ah_output_prefix = "";
static const char *ah_zip_password = "";
