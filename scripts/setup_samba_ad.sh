#!/bin/bash
# =============================================================================
# Samba Active Directory Domain Controller Setup
# Domain: onyx.local
# GCE e2-micro (free tier)
# =============================================================================
set -e

DOMAIN="ONYX"
REALM="ONYX.LOCAL"
ADMIN_PASS="OnyxAD2026!Secure"
DNS_FORWARDER="8.8.8.8"

echo "=== [1/7] Installing Samba AD DC ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq samba krb5-user krb5-config winbind smbclient \
    libpam-winbind libnss-winbind ldb-tools python3-samba acl attr

echo "=== [2/7] Configuring hostname ==="
hostnamectl set-hostname dc1
echo "127.0.0.1 dc1.onyx.local dc1" >> /etc/hosts
INTERNAL_IP=$(hostname -I | awk '{print $1}')
echo "$INTERNAL_IP dc1.onyx.local dc1" >> /etc/hosts

echo "=== [3/7] Stopping conflicting services ==="
systemctl stop smbd nmbd winbind 2>/dev/null || true
systemctl disable smbd nmbd winbind 2>/dev/null || true

# Backup and remove default config
mv /etc/samba/smb.conf /etc/samba/smb.conf.bak 2>/dev/null || true

echo "=== [4/7] Provisioning Samba AD DC ==="
samba-tool domain provision \
    --use-rfc2307 \
    --realm="$REALM" \
    --domain="$DOMAIN" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --adminpass="$ADMIN_PASS"

# Configure Kerberos
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

echo "=== [5/7] Configuring Samba as systemd service ==="
cat > /etc/systemd/system/samba-ad-dc.service << 'EOF'
[Unit]
Description=Samba Active Directory Domain Controller
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/sbin/samba -D
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/run/samba/samba.pid
LimitNOFILE=16384

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable samba-ad-dc
systemctl start samba-ad-dc

# Wait for Samba to start
sleep 5

echo "=== [6/7] Creating Organizational Units ==="
# Create OUs
samba-tool ou create "OU=Usuarios,DC=onyx,DC=local" --description="Usuarios ONYX"
samba-tool ou create "OU=TI,OU=Usuarios,DC=onyx,DC=local" --description="Tecnologia"
samba-tool ou create "OU=RRHH,OU=Usuarios,DC=onyx,DC=local" --description="Recursos Humanos"
samba-tool ou create "OU=Operaciones,OU=Usuarios,DC=onyx,DC=local" --description="Operaciones"
samba-tool ou create "OU=Grupos,DC=onyx,DC=local" --description="Grupos de seguridad"
samba-tool ou create "OU=ServiceAccounts,DC=onyx,DC=local" --description="Cuentas de servicio"

echo "=== [7/7] Creating Groups, Users & Service Account ==="

# Create security groups
samba-tool group add ONYX-Admins --groupou="OU=Grupos" --description="Administradores ONYX"
samba-tool group add ONYX-Analysts --groupou="OU=Grupos" --description="Analistas ONYX"
samba-tool group add ONYX-Viewers --groupou="OU=Grupos" --description="Visores ONYX"

# Create users — TI
samba-tool user create jhoan.ramirez "JhoanAD2026!" \
    --given-name="Jhoan" --surname="Ramirez" --mail-address="jramirez@agenticatech.ai" \
    --department="TI" --company="AgenticaTech" \
    --userou="OU=TI,OU=Usuarios"
samba-tool group addmembers ONYX-Admins jhoan.ramirez

samba-tool user create mario.herrera "MarioAD2026!" \
    --given-name="Mario" --surname="Herrera" --mail-address="mherrera@agenticatech.ai" \
    --department="TI" --company="AgenticaTech" \
    --userou="OU=TI,OU=Usuarios"
samba-tool group addmembers ONYX-Admins mario.herrera

samba-tool user create fernando.dev "FernandoAD2026!" \
    --given-name="Fernando" --surname="Developer" --mail-address="fdev@agenticatech.ai" \
    --department="TI" --company="AgenticaTech" \
    --userou="OU=TI,OU=Usuarios"
samba-tool group addmembers ONYX-Analysts fernando.dev

# Create users — RRHH
samba-tool user create jennifer.lopez "JenniferAD2026!" \
    --given-name="Jennifer" --surname="Lopez" --mail-address="jlopez@agenticatech.ai" \
    --department="RRHH" --company="AgenticaTech" \
    --userou="OU=RRHH,OU=Usuarios"
samba-tool group addmembers ONYX-Viewers jennifer.lopez

samba-tool user create maria.garcia "MariaAD2026!" \
    --given-name="Maria" --surname="Garcia" --mail-address="mgarcia@agenticatech.ai" \
    --department="RRHH" --company="AgenticaTech" \
    --userou="OU=RRHH,OU=Usuarios"
samba-tool group addmembers ONYX-Viewers maria.garcia

# Create users — Operaciones
samba-tool user create carlos.ops "CarlosAD2026!" \
    --given-name="Carlos" --surname="Operaciones" --mail-address="cops@agenticatech.ai" \
    --department="Operaciones" --company="AgenticaTech" \
    --userou="OU=Operaciones,OU=Usuarios"
samba-tool group addmembers ONYX-Analysts carlos.ops

samba-tool user create ana.martinez "AnaAD2026!" \
    --given-name="Ana" --surname="Martinez" --mail-address="amartinez@agenticatech.ai" \
    --department="Operaciones" --company="AgenticaTech" \
    --userou="OU=Operaciones,OU=Usuarios"
samba-tool group addmembers ONYX-Analysts ana.martinez

samba-tool user create pedro.ventas "PedroAD2026!" \
    --given-name="Pedro" --surname="Ventas" --mail-address="pventas@agenticatech.ai" \
    --department="Operaciones" --company="AgenticaTech" \
    --userou="OU=Operaciones,OU=Usuarios"
samba-tool group addmembers ONYX-Viewers pedro.ventas

samba-tool user create laura.admin "LauraAD2026!" \
    --given-name="Laura" --surname="Administracion" --mail-address="ladmin@agenticatech.ai" \
    --department="Operaciones" --company="AgenticaTech" \
    --userou="OU=Operaciones,OU=Usuarios"
samba-tool group addmembers ONYX-Analysts laura.admin

samba-tool user create diego.soporte "DiegoAD2026!" \
    --given-name="Diego" --surname="Soporte" --mail-address="dsoporte@agenticatech.ai" \
    --department="TI" --company="AgenticaTech" \
    --userou="OU=TI,OU=Usuarios"
samba-tool group addmembers ONYX-Analysts diego.soporte

# Create service account for LDAP bind
samba-tool user create svc-onyx-ldap "SvcOnyxLDAP2026!" \
    --given-name="Service" --surname="ONYX LDAP" --mail-address="svc-ldap@onyx.local" \
    --description="Service account for ONYX LDAP queries" \
    --userou="OU=ServiceAccounts"
# Set password never expires for service account
samba-tool user setexpiry svc-onyx-ldap --noexpiry

echo ""
echo "============================================"
echo " ✅ Samba AD DC Setup Complete!"
echo "============================================"
echo " Domain:     $REALM"
echo " Admin:      Administrator / $ADMIN_PASS"
echo " Internal IP: $INTERNAL_IP"
echo " LDAP Port:  389 (plaintext) / 636 (LDAPS)"
echo ""
echo " Users created: 10"
echo " Groups: ONYX-Admins, ONYX-Analysts, ONYX-Viewers"
echo " Service Account: svc-onyx-ldap / SvcOnyxLDAP2026!"
echo ""
echo " Test with: samba-tool user list"
echo " Test LDAP: ldapsearch -H ldap://localhost -x -D 'CN=svc-onyx-ldap,OU=ServiceAccounts,DC=onyx,DC=local' -w 'SvcOnyxLDAP2026!' -b 'DC=onyx,DC=local' '(objectClass=person)' cn mail"
echo "============================================"
