# AdaptiHound-BOF

A library of Beacon Object Files to collect Active Directory and FreeIPA graphs in AdaptixC2.
Supports Windows x64 beacon and gopher agents. Results are sent to Downloads as ZIP archives or individual JSON files.



## Build

Requires MinGW-w64 with `x86_64-w64-mingw32-g++` and `x86_64-w64-mingw32-strip`.

```sh
make
```

Use `make ad` or `make freeipa` to build one collector. Output files are `_bin/AdaptiHound/ad.x64.o` and `_bin/AdaptiHound/freeipa.x64.o`.

Load `postex.axs` through the AdaptixC2 AxScript manager. It imports `adaptihound.axs`, which connects the AD and FreeIPA command scripts.



## Structure

```text
postex.axs         AxScript entry point
adaptihound.axs    Shared arguments and command group
ADHound-BOF/
  ad.axs           Active Directory command
  src/
    core/          AD object model, settings and runtime
    collection/    LDAP producers, queries and target input
    graph/         BloodHound objects, relationships and output
    host/          Host probes, sessions and local groups
    registry/      Remote registry collection
    cache/         AD lookup cache
IPAHound-BOF/
  freeipa.axs      FreeIPA command
  src/
    core/          FreeIPA object model and runtime
    graph/         OpenGraph objects and relationships
  schema/          BloodHound graph definition
common/
  core/            Memory, arguments, logging and API imports
  ldap/            Shared LDAP transport and directory storage
  output/          JSON, ZIP and Downloads output
_include/          Bundled BOF API headers
mk/                Shared Make rules
```

Each collector has its own `src/entry.cpp` and `src/collector.cpp`. The FreeIPA build does not depend on AD collection modules.



## adaptihound ad

Collect Active Directory objects, memberships, ACLs, trusts, GPOs, certificate services and computer relationships.

```
adaptihound ad [--server DC] [--domain DOMAIN] [--collection METHODS] [--kerberos] [--ldaps]
```

* `--server` - Domain Controller FQDN (auto-detected if not specified)
* `--domain` - Domain to enumerate (current domain by default)
* `--searchforest` - Enumerate all domains in the forest
* `--recursedomains` - Recursively enumerate trusted domains
* `--base-dn` - LDAP search base (discovered from RootDSE by default)
* `--collection` - `default`, `dconly`, `computeronly`, `full`, `all`, `none`, or comma-separated collection methods
* `--kerberos` - Use Kerberos for LDAP authentication without NTLM fallback
* `--ldaps` - Require LDAPS
* `--port` - Plain LDAP port (389 by default)
* `--ssl-port` - LDAPS port (636 by default)
* `--ldap-username`, `--ldap-password` - Alternate LDAP credentials
* `--bind-dn`, `--password` - Explicit simple-bind credentials (requires `--ldaps`)
* `--disable-signing` - Disable signing and sealing on the plain LDAP fallback
* `--disable-cert-verification` - Disable LDAPS certificate validation
* `--ldap-filter` - Additional LDAP filter
* `--partition-ldap-queries` - Partition main LDAP queries by the first GUID byte
* `--page-size` - Entries per LDAP page (500 by default, maximum 1000)
* `--collect-all-properties` - Export additional readable LDAP attributes
* `--computers` - Comma-separated host targets for computer collection
* `--computer-file` - Read host targets from an operator-side file
* `--computer-file-agent` - Read host targets from a file on the collecting Windows host
* `--skip-registry-loggedon` - Skip HKEY_USERS session enumeration
* `--local-admin-session` - Use alternate local credentials for session enumeration
* `--local-admin-username`, `--local-admin-password` - Credentials for `--local-admin-session`
* `--override-username` - Accept the SharpHound compatibility option; the pinned session processor ignores it
* `--real-dns-name` - DNS suffix fallback when dNSHostName is absent
* `--throttle`, `--jitter` - Delay between computer requests in milliseconds and jitter percentage
* `--threads` - Concurrent object and host collectors (50 by default)
* `--extended-sessions` - Also collect WTS and WMI sessions
* `--conservative-probes` - Require additional evidence when classifying LDAP and HTTP policies
* `--skip-port-scan` - Skip the computer TCP 445 availability check
* `--skip-password-age-check` - Include computers with old password and logon timestamps
* `--port-scan-timeout` - TCP availability timeout in milliseconds (10000 by default)
* `--stealth` - Apply SharpHound 2.17.1 Stealth producer and method behavior
* `--exclude-dcs` - Skip ancillary Stealth DC discovery; ordinary DC collection remains enabled
* `--loop` - Repeat session, LoggedOn and local-group collection
* `--loop-duration` - Loop duration as a TimeSpan, such as `00:05:00` (zero selects two hours)
* `--loop-interval` - Delay between passes as a TimeSpan (zero selects 30 seconds)
* `--loop-duration-seconds`, `--loop-interval-seconds` - Integer-seconds aliases
* `--track-computer-calls` - Write computer collection status to CSV
* `--cache-name` - Lookup-cache path on the agent
* `--memcache` - Load an existing cache without creating or overwriting its file
* `--rebuild-cache` - Accept the compatibility flag; unused in SharpHound 2.17.1
* `--metrics` - Send LDAP collection metrics to Downloads

Collection methods include `group`, `localadmin`, `gpolocalgroup`, `session`, `loggedon`, `trusts`, `acl`, `container`, `rdp`, `dcom`, `psremote`, `objectprops`, `spntargets`, `userrights`, `caregistry`, `dcregistry`, `certservices`, `ldapservices`, `webclientservice`, `smbinfo`, `ntlmregistry`, `site` and `azureregistry`. Use `localgroup` to select the four local-group methods.

```
adaptihound ad --collection full
adaptihound ad --server dc.example.org --kerberos --collection dconly
adaptihound ad --collection session --computers workstation.example.org
```

AD output uses BloodHound v6 JSON. Collection behavior targets SharpHound 2.17.1 with SharpHoundCommon and SharpHoundRPC 4.9.1 (Stable), including repeated producer rows and the distinction between missing, null and empty values. The `None` method produces an empty ZIP unless `--no-zip` is set.

Import the AD ZIP or individual JSON files with BloodHound CE's native AD importer. AD data does not require a custom graph definition. An empty `None` archive contains no data to import.

Explicit empty strings are preserved, including `--output-prefix ""` and empty credential values. An empty computer-file path is rejected. An explicitly empty LDAP filter follows SharpHound's normalization to `()` and produces an LDAP filter error; omit the flag to use the generated filter alone.



## adaptihound freeipa

Collect FreeIPA users, groups, hosts, services, HBAC, sudo rules, permissions and trust relationships.

```
adaptihound freeipa --server SERVER --ldaps --bind-dn BIND_DN --password PASSWORD [--base-dn BASE_DN]
```

* `--server` - FreeIPA LDAP server FQDN (required)
* `--ldaps` - Use LDAPS (required)
* `--bind-dn` - LDAP bind distinguished name (required)
* `--password` - Bind password (required)
* `--base-dn` - LDAP search base (discovered from RootDSE by default)
* `--port` - LDAPS port (636 by default)
* `--page-size` - Entries per LDAP page (500 by default, maximum 1000)

FreeIPA always collects its complete configured set of object types. The shared `--collection` option is accepted for compatibility and does not select FreeIPA datasets. AD authentication, host collection, cache and forest traversal options are unavailable for this command.

```
adaptihound freeipa --server ipa.example.org --ldaps --bind-dn "uid=auditor,cn=users,cn=accounts,dc=example,dc=org" --password PASSWORD
```

FreeIPA output uses OpenGraph JSON. Install [ipahound-graph-definition.json](IPAHound-BOF/schema/ipahound-graph-definition.json) for the IPA node and edge definitions.

Update the installed graph definition to v1.1.0 for the `IPAHound` source kind and netgroup kinds used by the collector.

Node properties retain IPAHound's scalar types and newline-separated multivalued attributes. References to unreadable directory objects remain in the graph with their names and identifiers. Explicit sudo and CA ACL group targets remain group endpoints, and repeated rule relationships are preserved.



## Output options

Available for both collectors.

* `--output` - Base ZIP filename in Downloads; timestamp and optional prefix are still added
* `--output-prefix` - Prefix output filenames
* `--random-filenames` - Use random output filenames
* `--pretty-print` - Indent JSON output
* `--no-zip` - Send individual JSON files to Downloads
* `--zip-password` - Protect the ZIP archive with a password
* `--max-mib` - BOF-owned heap budget in MiB (0 grows with available memory)
* `--status-interval` - Status output interval in milliseconds (30000 by default)
* `--verbosity` - Log threshold from 0 (Trace) to 6 (None), default 2 (Information)

Default ZIP filenames:

| Command | Filename |
|---|---|
| `adaptihound ad` | `YYYYMMDDHHMMSS_adaptihound-ad-<domain>.zip` |
| `adaptihound freeipa` | `YYYYMMDDHHMMSS_adaptihound-freeipa-<domain>.zip` |

The domain is lowercase and the timestamp uses the collecting Windows host's local time. `--output-prefix PREFIX` adds `PREFIX_` before the timestamp. `--random-filenames` replaces the base filename and extension with random characters while retaining the timestamp and optional prefix.

With `--no-zip`, AD sends one JSON file per exported dataset and FreeIPA sends one `YYYYMMDDHHMMSS_freeipa_graph.json` file, with the same prefix and random-filename options.

Decrypt password-protected ZIPs and import the extracted JSON files. AD loop output includes an outer ZIP containing per-pass ZIPs; extract the outer archive and import the individual pass archives. When using random filenames, give extracted JSON files a `.json` extension for upload.



## References

* [SharpHound](https://github.com/SpecterOps/SharpHound)
* [IPAHound](https://github.com/IPAHound/IPAHound)
* [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2)
