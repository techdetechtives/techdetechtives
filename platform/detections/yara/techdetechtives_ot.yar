/*
  TechDetechtives OT (industrial control) rules for files carved from network traffic.
  Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).

  Names used here come from public reporting on the tools concerned.
*/

rule TechDetechtives_OT_Triton_Framework_Files
{
    meta:
        description = "Module and payload names of the TRITON/TRISIS attack framework for Triconex safety controllers"
        author = "TechDetechtives"
        date = "2026-10-05"
        severity = "critical"
    strings:
        $m1 = "TsHi" ascii
        $m2 = "TsBase" ascii
        $m3 = "TsLow" ascii
        $m4 = "TS_cnames" ascii
        $p1 = "inject.bin" ascii wide
        $p2 = "imain.bin" ascii wide
        $x1 = "trilog.exe" ascii wide nocase
    condition:
        filesize < 30MB and (3 of ($m*) or (all of ($p*) and 1 of ($m*, $x1)))
}

rule TechDetechtives_OT_Attack_Framework_SCADA_Modules
{
    meta:
        description = "Script or project that names Metasploit modules for scanning or attacking industrial control systems"
        author = "TechDetechtives"
        date = "2026-10-05"
        severity = "medium"
    strings:
        $m1 = "auxiliary/admin/scada/" ascii wide
        $m2 = "auxiliary/scanner/scada/" ascii wide
        $m3 = "exploit/windows/scada/" ascii wide
        $m4 = "auxiliary/dos/scada/" ascii wide
    condition:
        filesize < 5MB and any of them
}

rule TechDetechtives_OT_Script_Stops_Or_Reprograms_Controller
{
    meta:
        description = "Script that uses a PLC library call to stop a controller or load a program (hunting: expected only on engineering stations)"
        author = "TechDetechtives"
        date = "2026-10-05"
        severity = "low"
    strings:
        $lib1 = "import snap7" ascii
        $lib2 = "from snap7" ascii
        $lib3 = "pycomm3" ascii
        $lib4 = "pymodbus" ascii
        $act1 = ".plc_stop(" ascii
        $act2 = ".plc_cold_start(" ascii
        $act3 = ".full_upload(" ascii
        $act4 = ".download(" ascii
        $act5 = ".delete(" ascii
        $act6 = "write_coil" ascii
        $act7 = "write_register" ascii
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and
        ((1 of ($lib1, $lib2) and 1 of ($act1, $act2, $act3, $act4, $act5)) or
         (1 of ($lib3, $lib4) and 1 of ($act6, $act7) and #act6 + #act7 > 20))
}
