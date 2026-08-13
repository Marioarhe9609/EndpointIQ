#!/bin/bash
# Reset password with complexity and test
samba-tool user setpassword svc-onyx-ldap --newpassword='Onyx@Ldap2026!'
echo "=== Password reset ==="

# Try simple bind using samba-tool
echo "=== Testing with samba-tool ==="
samba-tool user show svc-onyx-ldap 2>&1 | head -10

# Try Python ldap3 directly (same as server.py will use)
echo "=== Testing with Python ldap3 ==="
python3 -c "
try:
    from ldap3 import Server, Connection, ALL
    server = Server('ldap://localhost', get_info=ALL, connect_timeout=5)
    conn = Connection(server, 
        user='CN=svc-onyx-ldap,OU=ServiceAccounts,DC=onyx,DC=local', 
        password='Onyx@Ldap2026!', 
        auto_bind=True, receive_timeout=10)
    print('BIND OK:', conn.bound)
    conn.search('DC=onyx,DC=local', '(&(objectClass=person)(mail=*))', attributes=['cn','mail'])
    for entry in conn.entries:
        print(f'  {entry.cn} -> {entry.mail}')
    conn.unbind()
except Exception as e:
    print('ERROR:', e)
" 2>&1

echo "=== DONE ==="
