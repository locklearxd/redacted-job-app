#!/bin/sh
# last modified 12/01/2023 alec

powershell create-security-alert.ps1 $@

sleep 5s

powershell sentinel-one-fortinet-network-isolation.ps1 $@
