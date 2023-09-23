rule sfx_pdb {

   meta:
      author = "@razvialex"
      description = "Detect interesting files containing sfx with pdb paths."
      date = "2022-07-12"
      yarahub_author_twitter = "@razvialex"
      yarahub_reference_md5 = "826108ccdfa62079420f7d8036244133"
      yarahub_uuid = "a9613562-42d2-41fd-a83a-e284332df92b"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"

   strings:
      $var1 = {0D786FA11A6028825A871437B4A067DF66AD67D833A5F938FE6EC930FD51CEF76D711BE7F24D203888A458DFC627FBFCAC32B8D15C96EC7722BB84E4A718812C4BB7A76563E2E43413E3A98A8AE4BA7DBA019CDBF07B3D4434E69B3C6DBC46D120ABB2F78192F0674CFEF4AA8EC682B5EA7C3F995610AA1C2B60F1BA730EC29BF769CFDE5AED1FA0A2479888B08F149C38AAE726B742E5}
      $var2 = "E<ul><li>Press <b>Install</b> button to start extraction.</li><br><br>E<ul><li>Press <b>Extract</b> button to start extraction.</li><br><br>6<li>Use <b>Browse</b> button to select the destination4folder fr" nocase ascii wide
      $var3 = {7E2024732572D181F9B8E4AE05150740623B7A4F5DA4CE3341E24F6D6D0F21F23356E55613C12597D7EB2884EB96D3773B491EAE2D1F472038AD96D1CEFA8ADBCDDE4E86C06855A15D69B2893C122471457D100000411C274A176E57AE62ECAA8922EFDDFBA2B6E4EFE117F2BD66338088B4373E2CB8BF91DEAC190864F4D44E6AFF350E6A}
      $var4 = {294424600F28F0660F6E5C241C660FFEF4660F6ED10F28C6660F6ECA660FEFC5660F62CA0F28E0660F72D00C660F72F414660FEFE0660F6E44242C660F62D80F28442460660F62D9660FFEDF660F6EF8660FFEDC660FEFC30F295C24500F28D8660F72D008660F72F318660FEFD80F28D3660F70DB39660FFED6}
      $var5 = {374DC673D0676DEA06A89B51F8F203C4A2E152A03A2310D7A9738544BAD912CF031887709B3ADC52E852B2E54EFB17072FA64DBEE1D7AB0A4FED628C7BECB9CE214066D4008315A1E675E3CCF2292F848100000000E4177764FBF5D3713D76A0E92F147D664CF4332EF1B8F38E0D0F1369944C73A80F26}
      $var6 = "lo haya hecho.\"\x0D\n\x0D\n; Dialog STARTDLG\x0D\n\x0D\n\x0D\n:DIALOG STARTDLG\x0D\n\x0D\nSIZE   " nocase ascii wide
      $var7 = "name=\"WinRAR SFX\"\x0D\n  type=\"win32\"/>\x0D\n<description>WinRAR SFX modu" nocase ascii
      $pdb = "Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" nocase ascii
      
   condition:
      $pdb and filesize < 3MB and 4 of ($var*)
}