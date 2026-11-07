var cmd_adaptihound_freeipa = ax.create_command("freeipa", "Collect FreeIPA objects, HBAC, sudo and permission relationships", "adaptihound freeipa --server dc.example.org --ldaps");
adaptihound_arguments(cmd_adaptihound_freeipa, "freeipa");
cmd_adaptihound_freeipa.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    adaptihound_collect(id, cmdline, parsed_json, "freeipa");
});
