#!/bin/sh
# TechDetechtives VMware lab: create the lab virtual switches and port groups.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Run in the ESXi host shell (SSH enabled under Host > Actions > Services), as root:
#   sh setup-network.sh            create everything (safe to re-run)
#   sh setup-network.sh --show     list what exists
#
# Creates two internal switches with no physical uplink. Only the router VM
# (OPNsense) connects them to the outside, through the existing "VM Network".
#
#   vSwitch-TD-MGMT   TD-MGMT    VLAN 0     10.10.10.0/24  platform, ticketing machine
#   vSwitch-TD-LAB    TD-IT      VLAN 20    10.10.20.0/24  endpoints, honeypot, attacker
#                     TD-OT      VLAN 30    10.10.30.0/24  OT simulators
#                     TD-SPAN    VLAN 4095  promiscuous    sensor monitor interface (sees IT + OT)
#
# TD-IT allows MAC changes and forged transmits, needed only for the layer 2
# attack tests (arpspoof, macof, macchanger) run from the attacker VM.
# ESXi's busybox /bin/sh is the interpreter: keep this POSIX.

set -eu

MGMT_SW="vSwitch-TD-MGMT"
LAB_SW="vSwitch-TD-LAB"

have_vswitch() { esxcli network vswitch standard list | grep -q "^$1\$"; }
have_pg() { esxcli network vswitch standard portgroup list | awk 'NR>2 {print $1}' | grep -qx "$1"; }

add_vswitch() {
  if have_vswitch "$1"; then echo "exists: $1"; else
    esxcli network vswitch standard add --vswitch-name="$1" --ports=128
    echo "created: $1"
  fi
}

add_pg() {  # name vswitch vlan
  if have_pg "$1"; then echo "exists: $1"; else
    esxcli network vswitch standard portgroup add --portgroup-name="$1" --vswitch-name="$2"
    echo "created: $1"
  fi
  esxcli network vswitch standard portgroup set --portgroup-name="$1" --vlan-id="$3"
}

if [ "${1:-}" = "--show" ]; then
  esxcli network vswitch standard list
  esxcli network vswitch standard portgroup list
  exit 0
fi

add_vswitch "$MGMT_SW"
add_vswitch "$LAB_SW"

# Switch-level security stays at the safe default (reject); exceptions are per port group.
for sw in "$MGMT_SW" "$LAB_SW"; do
  esxcli network vswitch standard policy security set --vswitch-name="$sw" \
    --allow-promiscuous=false --allow-mac-change=false --allow-forged-transmits=false
done

add_pg TD-MGMT "$MGMT_SW" 0
add_pg TD-IT   "$LAB_SW" 20
add_pg TD-OT   "$LAB_SW" 30
add_pg TD-SPAN "$LAB_SW" 4095

esxcli network vswitch standard portgroup policy security set --portgroup-name=TD-SPAN \
  --allow-promiscuous=true --allow-mac-change=false --allow-forged-transmits=false
esxcli network vswitch standard portgroup policy security set --portgroup-name=TD-IT \
  --allow-promiscuous=false --allow-mac-change=true --allow-forged-transmits=true
esxcli network vswitch standard portgroup policy security set --portgroup-name=TD-OT \
  --allow-promiscuous=false --allow-mac-change=false --allow-forged-transmits=false

echo
echo "Done. Port groups:"
esxcli network vswitch standard portgroup list | grep -E "TD-|Name"
echo
echo "Next: create the VMs (lab/README.md, phase 1). Attach the sensor's second"
echo "network card to TD-SPAN; it must not get an IP address."
