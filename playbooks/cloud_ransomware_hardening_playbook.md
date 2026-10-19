# Cloud Ransomware Incident Response & Hardening Playbook

**Framework:** Tri-Layer Defense-in-Depth (Perimeter, Cloud Fabric, Host)  
**Author:** Mark Bahaa (Lead DFIR Investigator, Inspire HUB)  
**Applicability:** Azure Hub-and-Spoke, FortiGate Next-Gen Firewalls, Windows Server & SQL Server Enterprise

---

## Layer 1: Perimeter Next-Gen Firewall (FortiOS) Hardening

### 1.1 Remediation of Over-Permissive Policies
Never allow `service ALL` on policies accepting ingress traffic from external interfaces (`port1` / WAN).

```fortios
config firewall policy
    edit 28
        set name "Hardened-Inbound-Access"
        set srcintf "port1"
        set dstintf "port2"
        # RESTRICTION: Replace 'all' with authorized management source IPs or VPN pool
        set srcaddr "Corp-HQ-Public-IP" "Authorized-Jumpbox"
        set dstaddr "Inbound-App-VIP"
        set action accept
        set schedule "always"
        # RESTRICTION: Replace 'ALL' with strictly inspected application services
        set service "HTTPS"
        # Security Profiles Activation
        set utm-status enable
        set ssl-ssh-profile "certificate-inspection"
        set ips-sensor "Enterprise-High-Security"
        set application-list "default"
        set logtraffic all
    next
end
```

### 1.2 Virtual IP (VIP) Port Forwarding Lockdown
Ensure VIP configurations explicitly enforce port forwarding rather than 1:1 full-port translation.

```fortios
config firewall vip
    edit "Inbound-App-VIP"
        set extip 10.50.20.4
        set mappedip "10.50.200.7"
        set extintf "port1"
        set portforward enable
        set protocol tcp
        set extport 443
        set mappedport 443
    next
end
```

---

## Layer 2: Azure Cloud SDN Hardening (Network Security Groups & Routing)

### 2.1 Hub & Spoke Network Security Groups (NSGs)
Apply explicit denial rules at the Azure VNet boundary to prevent uninspected transit.

```powershell
# PowerShell Azure CLI: Create NSG rule blocking direct internet access to database spoke
az network nsg rule create `
    --resource-group "Cloud-Prod-RG" `
    --nsg-name "NSG-Spoke-DatabaseTier" `
    --name "Deny-Direct-Internet-Inbound" `
    --priority 100 `
    --direction Inbound `
    --access Deny `
    --protocol Tcp `
    --source-address-prefixes Internet `
    --destination-port-ranges 1433 3389 445 139 `
    --destination-address-prefixes "10.50.200.0/24"
```

### 2.2 Forced Tunneling via User-Defined Routes (UDR)
Ensure all egress and lateral traffic from spokes is forcibly routed through the FortiGate inspection appliance (`10.50.200.4`):

```powershell
az network route-table route create `
    --resource-group "Cloud-Prod-RG" `
    --route-table-name "UDR-Spoke-Prod" `
    --name "Route-Spoke-Through-HubFGT" `
    --address-prefix "0.0.0.0/0" `
    --next-hop-type VirtualAppliance `
    --next-hop-ip-address "10.50.200.4"
```

---

## Layer 3: Host OS & Database Tier Hardening (MSSQL / Windows Server)

### 3.1 SQL Server CLR Assembly & Surface Lockdown
Run on production SQL Server instances to prevent arbitrary binary assembly loading and remote execution:

```sql
-- Disable CLR integration unless explicitly business-required
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'clr enabled', 0;
RECONFIGURE;

-- Disable xp_cmdshell execution
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- Ensure databases are NOT set to TRUSTWORTHY
ALTER DATABASE [ProductionDB] SET TRUSTWORTHY OFF;
```

### 3.2 Volume Shadow Copy & EDR Tamper Protection
- Enable **Microsoft Defender Tamper Protection** via Intune / Group Policy to prevent `dControl` registry manipulation.
- Restrict `vssadmin.exe` execution permissions to System/TrustedInstaller only.
- Implement immutable cloud backups (Azure Backup with Immutable Vault enabled).
