/*
  TechDetechtives OT IDS: rules for files carved from network traffic on a
  control network. They add to platform/detections/yara/techdetechtives_ot.yar.
  Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).

  Two kinds of rule:
    - controller programs and substation configurations in transit. These files
      are legitimate; the question a hit raises is whether this transfer, between
      these two machines, was expected. Severity is low on purpose.
    - names of industrial attack tools and malware components, taken from public
      reporting. They have not been checked against the malware itself.
*/

rule TechDetechtives_OT_Controller_Program_PLCopen_XML
{
    meta:
        description = "Controller program exported in the PLCopen XML exchange format (CODESYS and other IEC 61131-3 tools), moving over the network"
        author = "TechDetechtives"
        date = "2026-10-06"
        severity = "low"
    strings:
        $ns = "http://www.plcopen.org/xml/tc6_" ascii wide
        $p1 = "<project" ascii wide
        $p2 = "<pous>" ascii wide
        $p3 = "<pou " ascii wide
    condition:
        filesize < 50MB and $ns and $p1 and 1 of ($p2, $p3)
}

rule TechDetechtives_OT_Controller_Program_Rockwell_Export
{
    meta:
        description = "Rockwell Automation Logix controller project exported as L5X (XML) or L5K (text), moving over the network"
        author = "TechDetechtives"
        date = "2026-10-06"
        severity = "low"
    strings:
        $x1 = "<RSLogix5000Content" ascii wide
        $k1 = "IE_VER :=" ascii
        $k2 = "CONTROLLER " ascii
        $k3 = "ProcessorType :=" ascii
    condition:
        filesize < 100MB and ($x1 in (0..2048) or all of ($k*))
}

rule TechDetechtives_OT_Controller_Program_Schneider_Export
{
    meta:
        description = "Schneider Electric Unity Pro / Control Expert project exported as XEF (XML), moving over the network"
        author = "TechDetechtives"
        date = "2026-10-06"
        severity = "low"
    strings:
        $x1 = "<FEFExchangeFile" ascii wide
        $x2 = "<fileHeader" ascii wide
        $x3 = "<contentHeader" ascii wide
    condition:
        filesize < 100MB and $x1 and 1 of ($x2, $x3)
}

rule TechDetechtives_OT_Controller_Program_Source_Text
{
    meta:
        description = "Controller program source text (Siemens STL/SCL or IEC 61131-3 structured text) with complete block definitions, moving over the network"
        author = "TechDetechtives"
        date = "2026-10-06"
        severity = "low"
    strings:
        $o1 = "ORGANIZATION_BLOCK" ascii
        $o2 = "END_ORGANIZATION_BLOCK" ascii
        $f1 = "FUNCTION_BLOCK" ascii
        $f2 = "END_FUNCTION_BLOCK" ascii
        $d1 = "DATA_BLOCK" ascii
        $d2 = "END_DATA_BLOCK" ascii
        $v1 = "VAR_INPUT" ascii
        $v2 = "END_VAR" ascii
        $b1 = "BEGIN" ascii
    condition:
        filesize < 20MB and uint16(0) != 0x5A4D and
        (($o1 and $o2) or ($f1 and $f2) or ($d1 and $d2)) and 1 of ($v1, $v2, $b1)
}

rule TechDetechtives_OT_Substation_Configuration_IEC61850
{
    meta:
        description = "IEC 61850 substation configuration (SCL: .scd, .icd, .cid, .iid), which describes every protection device and its settings, moving over the network"
        author = "TechDetechtives"
        date = "2026-10-06"
        severity = "low"
    strings:
        $ns = "http://www.iec.ch/61850/2003/SCL" ascii wide
        $s1 = "<SCL" ascii wide
        $s2 = "<IED " ascii wide
        $s3 = "<Substation" ascii wide
        $s4 = "<DataTypeTemplates" ascii wide
    condition:
        filesize < 200MB and $ns and $s1 and 1 of ($s2, $s3, $s4)
}

rule TechDetechtives_OT_Scan_Script_Names_Industrial_Probes
{
    meta:
        description = "Script or command file that names three or more industrial-protocol probe scripts (Nmap and Digital Bond Redpoint), as a scan plan for control devices would"
        author = "TechDetechtives"
        date = "2026-10-06"
        severity = "medium"
    strings:
        $n1 = "s7-info" ascii wide
        $n2 = "modbus-discover" ascii wide
        $n3 = "enip-info" ascii wide
        $n4 = "bacnet-info" ascii wide
        $n5 = "omron-info" ascii wide
        $n6 = "pcworx-info" ascii wide
        $n7 = "fox-info" ascii wide
        $n8 = "codesys-v2-discover" ascii wide
        $n9 = "iec-identify" ascii wide
        $n10 = "dnp3-info" ascii wide
        $n11 = "s7-enumerate" ascii wide
        $n12 = "modicon-info" ascii wide
        $n13 = "BACnet-discover-enumerate" ascii wide
        $n14 = "enip-enumerate" ascii wide
        $n15 = "hartip-info" ascii wide
    condition:
        filesize < 5MB and 3 of them
}

rule TechDetechtives_OT_Exploitation_Framework_Names
{
    meta:
        description = "File that carries the name of the Industrial Exploitation Framework (ISF, icssploit) together with one of its controller-attack or scan module paths"
        author = "TechDetechtives"
        date = "2026-10-06"
        severity = "medium"
    strings:
        $f1 = "icssploit" ascii wide nocase
        $f2 = "Industrial Exploitation Framework" ascii wide nocase
        $m1 = "exploits/plcs/" ascii wide
        $m2 = "scanners/s7comm_scan" ascii wide
        $m3 = "scanners/vxworks_6_scan" ascii wide
        $m4 = "s7_300_400_plc_control" ascii wide
        $m5 = "quantum_140_plc_control" ascii wide
    condition:
        filesize < 20MB and 1 of ($f*) and 1 of ($m*)
}

rule TechDetechtives_OT_Industroyer_Component_Names
{
    meta:
        description = "File names of the Industroyer/CrashOverride components that spoke IEC 101, IEC 104, IEC 61850 and OPC DA to substation equipment (names from ESET's 2017 report)"
        author = "TechDetechtives"
        date = "2026-10-06"
        severity = "critical"
    strings:
        $w1 = "haslo.dat" ascii wide nocase
        $p1 = "101.dll" ascii wide nocase
        $p2 = "104.dll" ascii wide nocase
        $p3 = "61850.dll" ascii wide nocase
        $p4 = "OPCClientDemo.dll" ascii wide nocase
        $p5 = "61850.exe" ascii wide nocase
    condition:
        filesize < 30MB and (($w1 and 1 of ($p*)) or 3 of ($p*))
}

rule TechDetechtives_OT_Stuxnet_File_Names
{
    meta:
        description = "File names left by Stuxnet: the renamed Siemens STEP 7 communication library and its loader and driver files (names from Symantec's W32.Stuxnet dossier)"
        author = "TechDetechtives"
        date = "2026-10-06"
        severity = "critical"
    strings:
        $s1 = "s7otbxsx.dll" ascii wide nocase
        $t1 = "~WTR4141.tmp" ascii wide nocase
        $t2 = "~WTR4132.tmp" ascii wide nocase
        $d1 = "mrxcls.sys" ascii wide nocase
        $d2 = "mrxnet.sys" ascii wide nocase
    condition:
        filesize < 30MB and ($s1 or 2 of ($t*, $d*))
}
