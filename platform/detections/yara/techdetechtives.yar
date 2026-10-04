rule TechDetechtives_Script_Base64_Decode_And_Invoke
{
    meta:
        description = "Script text that decodes Base64 and invokes the result in the same file"
        author = "TechDetechtives"
        date = "2026-10-04"
        severity = "medium"
    strings:
        $decode = "FromBase64String" ascii wide nocase
        $invoke1 = "Invoke-Expression" ascii wide nocase
        $invoke2 = "IEX(" ascii wide nocase
        $invoke3 = "IEX (" ascii wide nocase
    condition:
        filesize < 2MB and $decode and any of ($invoke*)
}
