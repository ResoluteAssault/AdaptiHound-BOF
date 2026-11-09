var adaptihound_argument_schema = {};

function adaptihound_cli_tokens(line) {
    let tokens = [], value = "", quoted = false, started = false;
    for (let i = 0; i < line.length;) {
        let c = line[i];
        if ((c === " " || c === "\t") && !quoted) {
            if (started) tokens.push(value);
            value = ""; started = false; ++i; continue;
        }
        started = true;
        if (c === '"') { quoted = !quoted; ++i; continue; }
        if (c === "\\") {
            let count = 0;
            while (i < line.length && line[i] === "\\") { ++count; ++i; }
            if (line[i] === '"') {
                value += "\\".repeat(Math.floor(count / 2));
                if (count % 2) value += '"'; else quoted = !quoted;
                ++i;
            } else value += "\\".repeat(count);
        } else { value += c; ++i; }
    }
    if (quoted) throw new Error("Unterminated quoted argument");
    if (started) tokens.push(value);
    return tokens;
}

function adaptihound_restore_empty_arguments(line, parsed, backend) {
    let tokens = adaptihound_cli_tokens(line);
    if (tokens.indexOf("") < 0) return parsed;
    if (tokens[0] !== "adaptihound" || tokens[1] !== backend) throw new Error("Cannot recover empty arguments from this command line");
    let schema = adaptihound_argument_schema[backend], marks = {}, restored = Object.assign({}, parsed);
    for (let option of schema) {
        marks[option.mark] = option;
        delete restored[option.name];
        if (option.value !== undefined) restored[option.name] = option.value;
    }
    for (let i = 2; i < tokens.length; ++i) {
        let option = marks[tokens[i]];
        if (!option) throw new Error("Unknown argument: " + tokens[i]);
        if (option.type === "bool") { restored[option.name] = true; continue; }
        if (++i >= tokens.length) throw new Error("Missing value for " + option.mark);
        let value = tokens[i];
        if (option.type === "int") {
            if (!/^[+-]?\d+$/.test(value.trim()) || !Number.isSafeInteger(Number(value))) throw new Error("Invalid integer for " + option.mark);
            value = Number(value);
        }
        restored[option.name] = value;
    }
    return restored;
}

function adaptihound_target_file(path) {
    let encoded = ax.file_read(path);
    if (!encoded) throw new Error("Cannot read --computer-file through the extension's allowed file scope; use --computers or a readable file in the extension directory");
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", bytes = [];
    let bits = 0, value = 0;
    for (let i = 0; i < encoded.length; ++i) {
        if (encoded[i] === "=") break;
        let digit = alphabet.indexOf(encoded[i]);
        if (digit < 0) throw new Error("Invalid computer file encoding");
        value = ((value << 6) | digit) & 0xffffff; bits += 6;
        if (bits >= 8) { bits -= 8; bytes.push((value >> bits) & 255); }
    }
    let text = "";
    if (bytes.length >= 4 && ((bytes[0] === 255 && bytes[1] === 254 && bytes[2] === 0 && bytes[3] === 0) || (bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 254 && bytes[3] === 255))) {
        if (bytes.length % 4) throw new Error("Invalid UTF-32 computer file");
        let little = bytes[0] === 255, characters = [];
        for (let i = 4; i < bytes.length; i += 4) {
            let point = (little ? bytes[i] | bytes[i + 1] << 8 | bytes[i + 2] << 16 | bytes[i + 3] << 24 : bytes[i] << 24 | bytes[i + 1] << 16 | bytes[i + 2] << 8 | bytes[i + 3]) >>> 0;
            if (point > 0x10ffff || point >= 0xd800 && point <= 0xdfff) point = 0xfffd;
            if (point < 0x10000) characters.push(String.fromCharCode(point));
            else { point -= 0x10000; characters.push(String.fromCharCode(0xd800 | point >> 10, 0xdc00 | point & 1023)); }
        }
        text = characters.join("");
    } else if (bytes.length >= 2 && ((bytes[0] === 255 && bytes[1] === 254) || (bytes[0] === 254 && bytes[1] === 255))) {
        if (bytes.length % 2) throw new Error("Invalid UTF-16 computer file");
        let little = bytes[0] === 255, characters = [];
        for (let i = 2; i < bytes.length; i += 2) characters.push(String.fromCharCode(little ? bytes[i] | bytes[i + 1] << 8 : bytes[i] << 8 | bytes[i + 1]));
        text = characters.join("");
    } else {
        let escaped = [];
        for (let byte of bytes) escaped.push("%" + (byte < 16 ? "0" : "") + byte.toString(16));
        text = decodeURIComponent(escaped.join("")).replace(/^\uFEFF/, "");
    }
    return text;
}

function adaptihound_arguments(command, backend) {
    let registered = command, schema = [];
    command = {
        addArgFlagString: function (mark, name, description, value) {
            schema.push({mark: mark, name: name, type: "string", value: typeof description === "boolean" ? undefined : value});
            registered.addArgFlagString.apply(registered, arguments);
        },
        addArgFlagInt: function (mark, name, description, value) {
            schema.push({mark: mark, name: name, type: "int", value: value});
            registered.addArgFlagString(mark, name, description, String(value));
        },
        addArgBool: function (mark, description) {
            schema.push({mark: mark, name: mark, type: "bool", value: false});
            registered.addArgBool.apply(registered, arguments);
        }
    };
    command.addArgFlagString("--server", "server", "LDAP server FQDN (AD: discovers the current domain DC)", "");
    command.addArgFlagString("--domain", "domain", "AD: domain to enumerate", "");
    command.addArgBool("--searchforest", "AD: enumerate all domains in the forest");
    command.addArgBool("--recursedomains", "AD: recursively enumerate trusted domains");
    command.addArgFlagString("--base-dn", "base_dn", "Domain naming context; defaults to RootDSE discovery", "");
    command.addArgFlagString("--output", "output", "BloodHound ZIP filename in Downloads; defaults to adaptihound-" + backend + "-<domain>.zip", "");
    command.addArgFlagString("--bind-dn", "bind_dn", "Explicit LDAP bind DN; requires --ldaps", "");
    command.addArgFlagString("--password", "password", "Password for --bind-dn", "");
    command.addArgBool("--ldaps", "Use LDAPS with normal server certificate verification");
    command.addArgBool("--kerberos", "AD: restrict LDAP SSPI to Kerberos, without NTLM fallback");
    command.addArgFlagInt("--port", "port", "AD: plain LDAP port; FreeIPA/simple bind: LDAP or LDAPS port", 0);
    command.addArgFlagInt("--ssl-port", "ssl_port", "AD: LDAPS port; 0 selects 636", 0);
    command.addArgFlagString("--ldap-username", "ldap_username", false, "AD: alternate LDAP identity (DOMAIN\\user or UPN)");
    command.addArgFlagString("--ldap-password", "ldap_password", false, "AD: password for alternate LDAP identity; explicit empty password is supported");
    command.addArgBool("--disable-signing", "AD: disable LDAP signing and sealing on the plain LDAP fallback");
    command.addArgBool("--disable-cert-verification", "AD: explicitly disable LDAPS server certificate validation");
    command.addArgFlagString("--ldap-filter", "ldap_filter", false, "AD: add an LDAP filter to the generated producer queries");
    command.addArgBool("--partition-ldap-queries", "AD: partition main LDAP queries by the first GUID byte");
    command.addArgFlagInt("--page-size", "page_size", "Entries per LDAP page (1..1000)", 500);
    command.addArgFlagInt("--max-mib", "max_mib", "Total BOF-owned heap budget in MiB; 0 grows with available memory", 0);
    command.addArgBool("--memory-auto", "AD: economical streaming with memory allocated as needed; optional --max-mib hard ceiling covers BOF-owned heap only");
    command.addArgFlagString("--collection", "collection", "Collection mode: dconly, default or full", "default");
    command.addArgBool("--collect-all-properties", "AD: collect and export additional readable LDAP attributes");
    command.addArgFlagString("--computers", "computers", "AD: restrict host collection to comma-separated DNS names, account names or SIDs; LDAP graph remains available", "");
    command.addArgFlagString("--computer-file", "computer_file", false, "AD: host target list read through the extension's normal allowed file scope");
    command.addArgFlagString("--computer-file-agent", "computer_file_agent", false, "AD: stream a line-based target file on the collecting Windows host (SharpHound ComputerFile semantics)");
    command.addArgBool("--skip-registry-loggedon", "AD: omit HKEY_USERS LoggedOn enumeration");
    command.addArgFlagString("--override-username", "override_username", "AD: accepted for SharpHound 2.17.1 compatibility; its pinned session processor ignores this value", "");
    command.addArgFlagString("--real-dns-name", "real_dns_name", false, "AD: DNS suffix fallback when dNSHostName is absent (SharpHound 2.17.1)");
    command.addArgBool("--local-admin-session", "AD: use alternate local credentials for session APIs with default-credential fallback");
    command.addArgFlagString("--local-admin-username", "local_admin_username", false, "AD: local administrator identity for session enumeration");
    command.addArgFlagString("--local-admin-password", "local_admin_password", false, "AD: local administrator password; explicit empty password is supported");
    command.addArgFlagInt("--throttle", "throttle", "AD: delay before computer requests in milliseconds", 0);
    command.addArgFlagInt("--jitter", "jitter", "AD: throttle jitter percentage (0..100)", 0);
    command.addArgFlagInt("--threads", "threads", "AD: concurrent object and host collectors (positive Int32)", 50);
    command.addArgBool("--extended-sessions", "AD: also request WTS and WMI sessions");
    command.addArgBool("--conservative-probes", "AD: require additional evidence when classifying LDAP and HTTP policies");
    command.addArgBool("--pretty-print", "Indent JSON output");
    command.addArgBool("--no-zip", "Send individual JSON files to Downloads");
    command.addArgBool("--random-filenames", "Use random output filenames");
    command.addArgFlagString("--output-prefix", "output_prefix", false, "Prefix output filenames");
    command.addArgFlagString("--zip-password", "zip_password", "Protect the ZIP archive with a password", "");
    command.addArgBool("--track-computer-calls", "AD: write collection status CSV");
    command.addArgFlagString("--cache-name", "cache_name", "AD: lookup cache path on the agent; default uses the machine identity", "");
    command.addArgBool("--memcache", "AD: load an existing lookup cache but keep changes in memory");
    command.addArgBool("--rebuild-cache", "AD: accept the reference cache flag (unused in SharpHound 2.17.1)");
    command.addArgBool("--skip-port-scan", "AD: skip the computer TCP 445 availability check");
    command.addArgBool("--skip-password-age-check", "AD: include computer accounts with password and logon timestamps older than 60 days");
    command.addArgBool("--stealth", "AD: SharpHound 2.17.1 producer/method behavior; overrides computer filters without restricting host targets");
    command.addArgBool("--exclude-dcs", "AD: SharpHound 2.17.1 behavior: skip ancillary Stealth DC discovery; ordinary DC collection remains enabled");
    command.addArgFlagInt("--port-scan-timeout", "port_scan_timeout", "AD: computer availability TCP timeout in milliseconds", 10000);
    command.addArgBool("--loop", "AD: explicitly repeat Session, LoggedOn and local group collection after the initial graph");
    command.addArgFlagString("--loop-duration", "loop_duration", "AD: TimeSpan loop duration (d.hh:mm:ss.fffffff); 0 selects two hours", "00:00:00");
    command.addArgFlagString("--loop-interval", "loop_interval", "AD: TimeSpan delay between passes; 0 selects 30 seconds", "00:00:00");
    command.addArgFlagString("--loop-duration-seconds", "loop_duration_seconds", false, "AD: legacy integer-seconds duration alias");
    command.addArgFlagString("--loop-interval-seconds", "loop_interval_seconds", false, "AD: legacy integer-seconds interval alias");
    command.addArgBool("--telemetry", "Print detailed collection diagnostics and periodic progress to the console");
    command.addArgFlagInt("--status-interval", "status_interval", "Periodic console telemetry interval in milliseconds; requires --telemetry", 30000);
    command.addArgFlagInt("--verbosity", "verbosity", "Minimum log level: 0 trace, 1 debug, 2 information, 3 warning, 4 error, 5 critical, 6 none", 2);
    command.addArgBool("--metrics", "AD: export collection metrics to metrics.log in Downloads independently of console telemetry");
    adaptihound_argument_schema[backend] = schema;
}

function adaptihound_collect(id, cmdline, parsed_json, backend) {
    if (ax.arch(id) !== "x64") throw new Error("AdaptiHound requires a Windows x64 agent");
    parsed_json = adaptihound_restore_empty_arguments(cmdline, parsed_json, backend);
    for (let option of adaptihound_argument_schema[backend]) if (option.type === "int") {
        let value = parsed_json[option.name];
        if (typeof value !== "number" && (typeof value !== "string" || !/^[+-]?\d+$/.test(value.trim()))) throw new Error("Invalid integer for " + option.mark);
        value = Number(value);
        if (!Number.isSafeInteger(value)) throw new Error("Invalid integer for " + option.mark);
        parsed_json[option.name] = value;
    }
    let server = parsed_json["server"] || "";
    let user = parsed_json["bind_dn"] || "";
    let password = parsed_json["password"] || "";
    let tls = parsed_json["--ldaps"] ? 1 : 0;
    let kerberos = parsed_json["--kerberos"] ? 1 : 0;
    if (backend === "freeipa" && !server) throw new Error("FreeIPA requires --server");
    if (backend === "freeipa" && !user) throw new Error("FreeIPA requires --bind-dn, --password and --ldaps");
    if (backend === "freeipa" && kerberos) throw new Error("FreeIPA uses LDAPS simple bind; --kerberos is an AD option");
    if (user && (!tls || kerberos || !password)) throw new Error("--bind-dn requires --ldaps and --password, without --kerberos");
    if (!user && password) throw new Error("--password requires --bind-dn");
    let port = parsed_json["port"], pages = parsed_json["page_size"], mib = parsed_json["max_mib"];
    if (port < 0 || port > 65535 || pages < 1 || pages > 1000 || mib < 0 || mib > 2147483647) throw new Error("Invalid port, page size or memory limit");
    let memory_auto = parsed_json["--memory-auto"] ? 1 : 0;
    if (memory_auto) {
        if (backend !== "ad") throw new Error("--memory-auto requires AD");
        if (parsed_json["--stealth"] || parsed_json["--searchforest"] || parsed_json["--recursedomains"] ||
            parsed_json["computer_file"] || parsed_json["computer_file_agent"] || parsed_json["computers"])
            throw new Error("--memory-auto requires single-domain collection without Stealth, forest traversal or computer target filters");
    }
    let output = parsed_json["output"] || "";
    if (output && /[\\/:\x00-\x1f]/.test(output)) throw new Error("--output must be a ZIP filename");
    if (output && !/\.zip$/i.test(output)) output += ".zip";
    let collection = (parsed_json["collection"] || "default").toLowerCase();
    let methods = {
        dconly: 17040101, default: 23884779, full: 66057215, all: 66057215,
        group: 1, localadmin: 2, gpolocalgroup: 4, session: 8, loggedon: 16, trusts: 32,
        acl: 64, container: 128, rdp: 256, objectprops: 512, dcom: 4096, psremote: 16384,
        spntargets: 8192, userrights: 32768, caregistry: 65536, dcregistry: 131072,
        certservices: 262144, ldapservices: 524288, webclientservice: 2097152,
        smbinfo: 4194304, ntlmregistry: 8388608, site: 16777216, azureregistry: 33554432,
        computeronly: 48484618, localgroup: 20738, none: 0
    };
    let collection_mask = 0;
    for (let method of collection.split(",")) {
        let name = method.trim();
        if (!Object.prototype.hasOwnProperty.call(methods,name)) throw new Error("Unknown collection method: " + name);
        collection_mask |= methods[name];
    }
    let searchforest = parsed_json["--searchforest"] ? 1 : 0;
    let recursedomains = parsed_json["--recursedomains"] ? 1 : 0;
    if (backend === "freeipa" && (parsed_json["domain"] || searchforest || recursedomains)) throw new Error("Domain and forest traversal options require AD");
    let collect_all = parsed_json["--collect-all-properties"] ? 1 : 0;
    let target_text = parsed_json["computers"] || "";
    for (let key of ["computer_file", "computer_file_agent"]) {
        if (parsed_json[key] !== undefined && parsed_json[key] !== null && parsed_json[key] === "") throw new Error("ComputerFile requires a non-empty path");
    }
    let computer_file_text = parsed_json["computer_file"] ? adaptihound_target_file(parsed_json["computer_file"]) : "";
    let computer_file_agent = parsed_json["computer_file_agent"] || "";
    if ((parsed_json["computer_file"] ? 1 : 0) + (computer_file_agent ? 1 : 0) + (target_text ? 1 : 0) > 1) throw new Error("Choose --computer-file, --computer-file-agent or --computers");
    if (computer_file_text.indexOf("\0") >= 0 || computer_file_agent.indexOf("\0") >= 0) throw new Error("ComputerFile input contains a NUL character");
    let targets = [];
    for (let target of target_text.split(/[,\r\n]+/)) {
        target = target.trim();
        if (!target || target[0] === "#") continue;
        if (/[\x00-\x1f\x7f]/.test(target)) throw new Error("Invalid control character in computer target");
        if (targets.indexOf(target) < 0) targets.push(target);
    }
    if (parsed_json["computers"] && !targets.length) throw new Error("Computer target list is empty");
    if (backend === "freeipa" && (collect_all || targets.length || parsed_json["computer_file"] || computer_file_agent)) throw new Error("--collect-all-properties and computer target filters are AD options");
    let skip_port = parsed_json["--skip-port-scan"] ? 1 : 0, skip_age = parsed_json["--skip-password-age-check"] ? 1 : 0, loop = parsed_json["--loop"] ? 1 : 0;
    let has_duration_seconds = parsed_json["loop_duration_seconds"] !== undefined && parsed_json["loop_duration_seconds"] !== null;
    let has_interval_seconds = parsed_json["loop_interval_seconds"] !== undefined && parsed_json["loop_interval_seconds"] !== null;
    let loop_duration = has_duration_seconds ? String(parsed_json["loop_duration_seconds"]) : String(parsed_json["loop_duration"] === undefined ? "00:00:00" : parsed_json["loop_duration"]);
    let loop_interval = has_interval_seconds ? String(parsed_json["loop_interval_seconds"]) : String(parsed_json["loop_interval"] === undefined ? "00:00:00" : parsed_json["loop_interval"]);
    let scan_timeout = parsed_json["port_scan_timeout"] === undefined ? 10000 : parsed_json["port_scan_timeout"];
    if (scan_timeout < 1 || scan_timeout > 2147483647) throw new Error("Invalid port-scan timeout");
    if (loop_duration.indexOf("\0") >= 0 || loop_interval.indexOf("\0") >= 0) throw new Error("Invalid TimeSpan");
    let stealth = parsed_json["--stealth"] ? 1 : 0, exclude_dcs = parsed_json["--exclude-dcs"] ? 1 : 0;
    let effective_methods = collection_mask;
    if (stealth) {
        effective_methods &= ~(16 | 20738 | 65536 | 131072 | 8388608 | 33554432);
        if (collection_mask & 20738) effective_methods |= 4;
    }
    if (backend === "freeipa" && (loop || skip_port || skip_age || stealth || exclude_dcs)) throw new Error("Loop and availability options require AD");
    let flags = collect_all | (skip_port << 1) | (skip_age << 2) | (loop << 3) | (stealth << 4) | (exclude_dcs << 5);
    let runtime_flags = 0;
    let switches = ["--skip-registry-loggedon", "--disable-signing", "--disable-cert-verification", "--partition-ldap-queries", "--local-admin-session", "--extended-sessions", "--conservative-probes", null, "--pretty-print", "--no-zip", "--random-filenames", "--track-computer-calls", "--memcache", "--rebuild-cache", "--memory-auto"];
    for (let i = 0; i < switches.length; ++i) if (switches[i] && parsed_json[switches[i]]) runtime_flags |= 1 << i;
    if (parsed_json["computer_file"] || computer_file_agent) runtime_flags |= 128;
    let extra = ["ldap_filter", "ldap_username", "ldap_password", "local_admin_username", "local_admin_password", "override_username", "real_dns_name", "output_prefix", "zip_password", "cache_name"];
    let extra_values = extra.map(function (key) { return parsed_json[key] || ""; });
    if (extra_values.some(function (value) { return value.indexOf("\0") >= 0; })) throw new Error("Invalid extended argument");
    let has_ldap_user = parsed_json["ldap_username"] !== undefined && parsed_json["ldap_username"] !== null;
    let has_ldap_password = parsed_json["ldap_password"] !== undefined && parsed_json["ldap_password"] !== null;
    if (has_ldap_user !== has_ldap_password) throw new Error("Specify both --ldap-username and --ldap-password; use an explicit empty string for an empty password");
    if ((parsed_json["ldap_password"] && !parsed_json["ldap_username"]) || (user && has_ldap_user)) throw new Error("Use one LDAP authentication mode");
    let local_user_present = parsed_json["local_admin_username"] !== undefined && parsed_json["local_admin_username"] !== null;
    let local_password_present = parsed_json["local_admin_password"] !== undefined && parsed_json["local_admin_password"] !== null;
    if ((runtime_flags & 16) && (!local_user_present || !local_password_present)) throw new Error("--local-admin-session requires local administrator username and password (explicit empty strings are accepted)");
    if ((local_user_present || local_password_present) && !(runtime_flags & 16)) throw new Error("Local administrator credentials require --local-admin-session");
    let ssl_port = parsed_json["ssl_port"] || 0, throttle = parsed_json["throttle"] || 0, jitter = parsed_json["jitter"] || 0;
    let threads = parsed_json["threads"] === undefined ? 50 : parsed_json["threads"];
    if (ssl_port < 0 || ssl_port > 65535 || throttle < 0 || throttle > 2147483647 || jitter < 0 || jitter > 100) throw new Error("Invalid LDAPS port, throttle or jitter");
    if (threads < 1 || threads > 2147483647) throw new Error("Invalid thread count");
    let status_interval = parsed_json["status_interval"] === undefined ? 30000 : parsed_json["status_interval"];
    let verbosity = parsed_json["verbosity"] === undefined ? 2 : parsed_json["verbosity"];
    if (status_interval < 1 || status_interval > 2147483647 || verbosity < -2147483648 || verbosity > 2147483647) throw new Error("Invalid status interval or verbosity");
    if (parsed_json["output_prefix"] && /[\\/:\x00-\x1f]/.test(parsed_json["output_prefix"])) throw new Error("Invalid output filename prefix");
    if (backend === "freeipa" && (runtime_flags & 12543 || parsed_json["cache_name"] || (parsed_json["ldap_filter"] !== undefined && parsed_json["ldap_filter"] !== null) || has_ldap_user || has_ldap_password || local_user_present || local_password_present || parsed_json["override_username"] || (parsed_json["real_dns_name"] !== undefined && parsed_json["real_dns_name"] !== null) || ssl_port || throttle || jitter || parsed_json["--track-computer-calls"] || parsed_json["--metrics"] || has_duration_seconds || has_interval_seconds)) throw new Error("Selected runtime options require AD");
    let option_presence = (parsed_json["--metrics"] ? 1 : 0) | (has_duration_seconds ? 2 : 0) | (has_interval_seconds ? 4 : 0) |
        (local_user_present ? 8 : 0) | (local_password_present ? 16 : 0) | (parsed_json["computer_file"] ? 32 : 0) | (computer_file_agent ? 64 : 0) |
        (parsed_json["ldap_filter"] !== undefined && parsed_json["ldap_filter"] !== null ? 128 : 0) | (parsed_json["output_prefix"] !== undefined && parsed_json["output_prefix"] !== null ? 256 : 0) |
        (parsed_json["real_dns_name"] !== undefined && parsed_json["real_dns_name"] !== null ? 512 : 0) | (parsed_json["--telemetry"] ? 1024 : 0);
    let values = [server, parsed_json["base_dn"] || "", output, user, password, tls, kerberos, port, pages, mib, collection_mask, parsed_json["domain"] || "", searchforest, recursedomains, parsed_json["--telemetry"] ? 7 : memory_auto ? 6 : 5, flags, targets.join(","), 7200, 30, scan_timeout, runtime_flags].concat(extra_values, [ssl_port, throttle, jitter, threads, status_interval, loop_duration, loop_interval, computer_file_agent, computer_file_text, option_presence, verbosity]);
    let format = "cstr,cstr,cstr,cstr,cstr,int,int,int,int,int,int,cstr,int,int,int,int,cstr,int,int,int,int,cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr,int,int,int,int,int,cstr,cstr,cstr,cstr,int,int";
    let bof_params = ax.bof_pack(format, values);
    let bof_path = ax.script_dir() + "_bin/AdaptiHound/" + backend + "." + ax.arch(id) + ".o";
    let cmd = "execute bof";
    let task_desc = "AdaptiHound: collect " + backend + " directory graph";
    ax.execute_alias(id, cmdline, `${cmd} ${bof_path} ${bof_params}`, task_desc);
}

ax.script_import(ax.script_dir() + "ADHound-BOF/ad.axs");
ax.script_import(ax.script_dir() + "IPAHound-BOF/freeipa.axs");

var cmd_adaptihound = ax.create_command("adaptihound", "Collect Active Directory or FreeIPA graph data", "adaptihound {ad|freeipa} [options]");
cmd_adaptihound.addSubCommands([cmd_adaptihound_ad, cmd_adaptihound_freeipa]);

var group_adaptihound = ax.create_commands_group("AdaptiHound-BOF", [cmd_adaptihound]);
ax.register_commands_group(group_adaptihound, ["beacon", "gopher"], ["windows"], []);
