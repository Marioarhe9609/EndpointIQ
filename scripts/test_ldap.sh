#!/bin/bash
samba-tool user setpassword svc-onyx-ldap --newpassword=OnyxLDAP2026
echo "Password reset OK"
sleep 1
ldapsearch -H ldap://localhost -x -D "CN=svc-onyx-ldap,OU=ServiceAccounts,DC=onyx,DC=local" -w "OnyxLDAP2026" -b "DC=onyx,DC=local" "(&(objectClass=person)(mail=*))" cn mail -LLL 2>&1 | head -40
echo "=== DONE ==="
