# Sample data

Synthetic events written for TechDetechtives. They are not captured from any real
network. Host names, users and addresses are invented; external addresses use
the documentation ranges 203.0.113.0/24 and 198.51.100.0/24.

The data tells one small story for the notebooks to find: a network logon by
`svc_backup` from 10.20.30.45 to `srv-file01`, followed by remote WMI execution
(WmiPrvSE.exe starting an encoded, hidden PowerShell), discovery commands, and
regular outbound connections to 203.0.113.50.
