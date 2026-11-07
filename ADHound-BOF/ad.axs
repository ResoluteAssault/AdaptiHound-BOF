var cmd_adaptihound_ad = ax.create_command("ad", "Collect AD objects, group memberships, trusts and ACLs", "adaptihound ad --server dc.example.org --ldaps");
adaptihound_arguments(cmd_adaptihound_ad, "ad");
cmd_adaptihound_ad.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    adaptihound_collect(id, cmdline, parsed_json, "ad");
});
