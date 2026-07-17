#!/bin/bash
set -e

samba-tool ou create "OU=Usuarios,DC=onyx,DC=local" 2>/dev/null || true
samba-tool ou create "OU=TI,OU=Usuarios,DC=onyx,DC=local" 2>/dev/null || true
samba-tool ou create "OU=RRHH,OU=Usuarios,DC=onyx,DC=local" 2>/dev/null || true
samba-tool ou create "OU=Operaciones,OU=Usuarios,DC=onyx,DC=local" 2>/dev/null || true
samba-tool ou create "OU=Grupos,DC=onyx,DC=local" 2>/dev/null || true
samba-tool ou create "OU=ServiceAccounts,DC=onyx,DC=local" 2>/dev/null || true

samba-tool group add ONYX-Admins --groupou="OU=Grupos" 2>/dev/null || true
samba-tool group add ONYX-Analysts --groupou="OU=Grupos" 2>/dev/null || true
samba-tool group add ONYX-Viewers --groupou="OU=Grupos" 2>/dev/null || true

samba-tool user create jhoan.ramirez "JhoanAD2026!" --given-name=Jhoan --surname=Ramirez --mail-address=jramirez@agenticatech.ai --department=TI --userou="OU=TI,OU=Usuarios" 2>/dev/null || true
samba-tool group addmembers ONYX-Admins jhoan.ramirez 2>/dev/null || true
samba-tool user create mario.herrera "MarioAD2026!" --given-name=Mario --surname=Herrera --mail-address=mherrera@agenticatech.ai --department=TI --userou="OU=TI,OU=Usuarios" 2>/dev/null || true
samba-tool group addmembers ONYX-Admins mario.herrera 2>/dev/null || true
samba-tool user create fernando.dev "FernandoAD2026!" --given-name=Fernando --surname=Developer --mail-address=fdev@agenticatech.ai --department=TI --userou="OU=TI,OU=Usuarios" 2>/dev/null || true
samba-tool group addmembers ONYX-Analysts fernando.dev 2>/dev/null || true
samba-tool user create jennifer.lopez "JenniferAD2026!" --given-name=Jennifer --surname=Lopez --mail-address=jlopez@agenticatech.ai --department=RRHH --userou="OU=RRHH,OU=Usuarios" 2>/dev/null || true
samba-tool group addmembers ONYX-Viewers jennifer.lopez 2>/dev/null || true
samba-tool user create maria.garcia "MariaAD2026!" --given-name=Maria --surname=Garcia --mail-address=mgarcia@agenticatech.ai --department=RRHH --userou="OU=RRHH,OU=Usuarios" 2>/dev/null || true
samba-tool group addmembers ONYX-Viewers maria.garcia 2>/dev/null || true
samba-tool user create carlos.ops "CarlosAD2026!" --given-name=Carlos --surname=Operaciones --mail-address=cops@agenticatech.ai --department=Operaciones --userou="OU=Operaciones,OU=Usuarios" 2>/dev/null || true
samba-tool group addmembers ONYX-Analysts carlos.ops 2>/dev/null || true
samba-tool user create ana.martinez "AnaAD2026!" --given-name=Ana --surname=Martinez --mail-address=amartinez@agenticatech.ai --department=Operaciones --userou="OU=Operaciones,OU=Usuarios" 2>/dev/null || true
samba-tool group addmembers ONYX-Analysts ana.martinez 2>/dev/null || true
samba-tool user create diego.soporte "DiegoAD2026!" --given-name=Diego --surname=Soporte --mail-address=dsoporte@agenticatech.ai --department=TI --userou="OU=TI,OU=Usuarios" 2>/dev/null || true
samba-tool group addmembers ONYX-Analysts diego.soporte 2>/dev/null || true
samba-tool user create svc-onyx-ldap "SvcOnyxLDAP2026!" --given-name=Service --surname=ONYX --mail-address=svc-ldap@onyx.local --userou="OU=ServiceAccounts" 2>/dev/null || true
samba-tool user setexpiry svc-onyx-ldap --noexpiry 2>/dev/null || true

echo "=== USERS ==="
samba-tool user list
echo "=== ADMINS ==="
samba-tool group listmembers ONYX-Admins
echo "=== ANALYSTS ==="
samba-tool group listmembers ONYX-Analysts
echo "=== VIEWERS ==="
samba-tool group listmembers ONYX-Viewers
