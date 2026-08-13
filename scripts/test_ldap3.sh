#!/bin/bash
pip3 install ldap3 -q 2>/dev/null
python3 << 'PYEOF'
from ldap3 import Server, Connection, ALL
s = Server('ldap://localhost', get_info=ALL, connect_timeout=5)
c = Connection(s, 
    user='CN=svc-onyx-ldap,OU=ServiceAccounts,DC=onyx,DC=local', 
    password='Onyx@Ldap2026!', 
    auto_bind=True, receive_timeout=10)
print('BOUND:', c.bound)
c.search('DC=onyx,DC=local', '(&(objectClass=person)(mail=*))', attributes=['cn','mail','memberOf','department'])
for entry in c.entries:
    groups = [str(g).split(',')[0].replace('CN=','') for g in entry.memberOf] if hasattr(entry,'memberOf') and entry.memberOf else []
    print(f'  {entry.cn} | {entry.mail} | dept={entry.department} | groups={groups}')
c.unbind()
print('=== LDAP WORKING ===')
PYEOF
