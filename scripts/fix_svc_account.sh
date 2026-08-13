#!/bin/bash
# Delete and recreate svc-onyx-ldap with a simple password
samba-tool user delete svc-onyx-ldap 2>/dev/null
echo "Deleted old svc-onyx-ldap"

# Create fresh with a known password
samba-tool user create svc-onyx-ldap 'P@ssw0rd2026Ldap' \
    --given-name=Service --surname=ONYX \
    --mail-address=svc-ldap@onyx.local \
    --userou="OU=ServiceAccounts"
samba-tool user setexpiry svc-onyx-ldap --noexpiry
echo "Created svc-onyx-ldap with new password"

# Test with ldapsearch
echo "=== Testing ldapsearch ==="
ldapsearch -H ldap://localhost -x \
    -D "CN=Service ONYX,OU=ServiceAccounts,DC=onyx,DC=local" \
    -w 'P@ssw0rd2026Ldap' \
    -b "DC=onyx,DC=local" \
    "(&(objectClass=person)(mail=*))" cn mail -LLL 2>&1 | head -40

# Test with Python ldap3
echo ""
echo "=== Testing Python ldap3 ==="
python3 << 'PYEOF'
from ldap3 import Server, Connection, ALL
s = Server('ldap://localhost', get_info=ALL, connect_timeout=5)
c = Connection(s, 
    user='CN=Service ONYX,OU=ServiceAccounts,DC=onyx,DC=local', 
    password='P@ssw0rd2026Ldap', 
    auto_bind=True, receive_timeout=10)
print('BOUND:', c.bound)
c.search('DC=onyx,DC=local', '(&(objectClass=person)(mail=*))', attributes=['cn','mail','memberOf','department'])
for entry in c.entries:
    groups = [str(g).split(',')[0].replace('CN=','') for g in entry.memberOf] if hasattr(entry,'memberOf') and entry.memberOf else []
    print(f'  {entry.cn} | {entry.mail} | groups={groups}')
c.unbind()
print('=== LDAP WORKING ===')
PYEOF
