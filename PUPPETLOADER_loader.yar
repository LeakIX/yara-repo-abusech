rule PUPPETLOADER_loader {
  meta:
    date = "2022-06-13"
    author = "Willi Ballenthin"
    yarahub_author_email = "william.ballenthin@mandiant.com"
    yarahub_author_twitter = "@williballenthin"
    yarahub_uuid = "87d14a7a-047f-4db2-83a9-1b0bd5097e1e"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "7fdeb5fb041463416620cf9f446532e4"
  strings:
        $a1 = "PuppetLoader.Puppet.Core.x64.Release" ascii wide
        $a2 = "PuppetLoader.Puppet.Core" ascii wide
        $a3 = "HijacjBmpPath" ascii wide
        $a4 = "dwOriginBmpFileSize" ascii wide
        $a5 = "TsClientReceptor_Core" ascii wide
        $a6 = "PuppetLoader_Puppet_Core" ascii wide
        $a7 = "TsClientReceptor.Install" ascii wide
        $a8 = "l UnExist [" ascii wide
        $a9 = "] Faild! Error" ascii wide
        $a10 = "GUID_Common_FileShareMemoryName" ascii wide
        $a11 = "GUID_Common_ShareMemoryName" ascii wide
        $a12 = "GUID_CrackWinPassword_x64_Release" ascii wide
        $a13 = "GUID_KeepAuthority_Launcher_Core_x64_Release" ascii wide
        $a14 = "GUID_KeepAuthority_MainConsole_x64_Release" ascii wide
        $a15 = "GUID_KeepAuthority_Service_Hijacker" ascii wide
        $a16 = "GUID_PuppetLoader_Puppet_Core_x64_Release" ascii wide
        $a17 = "GUID_PuppetLoader_Puppet_Shell_x64_Release" ascii wide
        $a18 = "GUID_TsClientReceptor_Core_PreventRepeatRunning_MutexName" ascii wide
        $a19 = "GUID_TsClientReceptor_Core_x64_Release" ascii wide
        $a20 = "Mutex_KeepAuthority_Launcher_Core_x64_Release" ascii wide
        $a21 = "[+] SendParam to [Explorer.exe] for Load TsClientReceptor" ascii wide
        $a22 = "[+] TsClientReceptor.Install.Injector [Explorer.exe]" ascii wide
        $a23 = "[-] Injector to [Explorer.exe] Faild! Error" ascii wide
        $a24 = "[-] Puppet.Shell UnExist [Puppet.Core.x64.Release]" ascii wide
        $g1 = "{0137C4B3-9511-54A1-DAFA-EF5916E42AE7}" ascii wide
        $g2 = "{07243368-21B1-22F0-9757-49A405B4DDF1}" ascii wide
        $g3 = "{09884BAB-D4AD-1969-8807-A4AE797A8C31}" ascii wide
        $g4 = "{0D287554-3E48-C081-1EEE-6E73FA4749E1}" ascii wide
        $g5 = "{0DDC8939-E627-3895-4CDA-A703C54AF86F}" ascii wide
        $g6 = "{0E0E5273-C9DC-03FB-7830-014DD7143F48}" ascii wide
        $g7 = "{27737527-D71F-1A85-081D-080A2F6A10E1}" ascii wide
        $g8 = "{2D606381-46DB-0AFC-325B-9687FB5E86CB}" ascii wide
        $g9 = "{36BF388E-8509-E892-430C-D0ABC3038CE6}" ascii wide
        $g10 = "{3A8163C4-1D40-DFD0-AB78-BEF1C8423439}" ascii wide
        $g11 = "{409A21C9-45D9-A0C9-5564-E3647EC26CB0}" ascii wide
        $g12 = "{46B0888B-0941-52E6-6FBA-80F04E425935}" ascii wide
        $g13 = "{4AF0C1F6-714E-A36C-428D-851DC708EF2B}" ascii wide
        $g14 = "{4F97AB75-B463-0399-D30E-FC22B4596D64}" ascii wide
        $g15 = "{54A4A30A-C06A-3EE6-C36D-0F84820221CA}" ascii wide
        $g16 = "{6ED6C950-9133-A1C5-A010-EC27B06C80B6}" ascii wide
        $g17 = "{73303282-8959-6FA7-2DBE-E4126D8B6634}" ascii wide
        $g18 = "{78106D5F-CD1A-A8C4-A625-6863092B4BBA}" ascii wide
        $g19 = "{7D8DA9DC-1F3B-2E5C-AA59-9418E652E4AA}" ascii wide
        $g20 = "{8341B127-B109-66A3-9F23-E9C52D6309BE}" ascii wide
        $g21 = "{94262E6D-AC4C-89C5-C380-668F0CBA9F4C}" ascii wide
        $g22 = "{A20827CB-C06C-967E-00AD-C6BDC9B3C8B8}" ascii wide
        $g23 = "{A31EACD0-359E-2FDD-D0DF-C253F2BCE623}" ascii wide
        $g24 = "{ADB3515D-426D-B1BB-6EA4-DCD760485C82}" ascii wide
        $g25 = "{AFE10005-B7DF-352C-1F79-FAEE9EF6BB5C}" ascii wide
        $g26 = "{B27FAFB3-62A8-DE16-360A-2F5FEE4F5B97}" ascii wide
        $g27 = "{B573FEAA-9F11-9459-5A70-25687347EEF6}" ascii wide
        $g28 = "{B5A7BDC2-0FAC-3EE8-B382-7A32599C3C0F}" ascii wide
        $g29 = "{B97CBA44-A361-1602-2934-7D08A4E1F49F}" ascii wide
        $g30 = "{CE2A883F-04FA-B568-6788-F3D29780989D}" ascii wide
        $g31 = "{D11BE42E-763C-5134-93AA-1F618C8F3C56}" ascii wide
        $g32 = "{D47CBD52-96C3-1B68-2C88-84D495F8C7A1}" ascii wide
        $g33 = "{E9F0F295-7A48-C9ED-6696-3B4D2BBEC787}" ascii wide
        $g34 = "{EA205CF8-4CC4-4FBB-E430-AF497368CF46}" ascii wide
        $g35 = "{F032FD6E-C8EE-EDFC-0ECD-41C2BA46965B}" ascii wide
        $g36 = "{F198C4FF-5133-EFEA-C6FC-330B9AF9E208}" ascii wide
    condition:
        any of ($a*) or 5 of ($g*)
}