# 00 : montage du lab

Objectif : un domaine `lab.internal` fonctionnel sur un réseau virtuel isolé, avec
des faiblesses **volontaires et documentées** (une par scénario), et des snapshots
pour revenir à un état propre entre deux essais.

> Les mots de passe du lab sont fictifs et n'existent que dans les VM. Je ne les
> commite pas : je les note dans un gestionnaire de mots de passe local.

## 1. Matériel et images

| VM | Système | vCPU | RAM | Disque | IP |
|---|---|---|---|---|---|
| DC01 | Windows Server 2022 (évaluation 180 jours) | 2 | 4 Go | 60 Go | 10.10.10.10 |
| SRV01 | Windows Server 2022 (évaluation) | 2 | 4 Go | 60 Go | 10.10.10.20 |
| CLIENT01 | Windows 11 Entreprise (évaluation) | 2 | 4 Go | 64 Go | 10.10.10.30 |
| KALI | Kali Linux (image VirtualBox officielle) | 2 | 4 Go | 80 Go | 10.10.10.50 |
| WAZUH | Ubuntu Server 24.04 LTS + Wazuh (tout-en-un) | 4 | 8 Go | 80 Go | 10.10.10.100 |

Total : environ 24 Go de RAM si tout tourne en même temps. Avec moins de mémoire,
je n'allume que les VM utiles au scénario en cours (DC01, Wazuh et Kali suffisent
pour les scénarios 2 et 5).

Les images d'évaluation viennent du Microsoft Evaluation Center. Je vérifie
l'empreinte SHA-256 de chaque ISO avant de l'utiliser.

> **Note sur la version :** je reste sur Windows Server 2022 pour que les
> scénarios soient reproductibles. Les versions plus récentes durcissent Kerberos
> par défaut (RC4 désactivé ou restreint). Si un test donne un résultat différent
> sur une version récente, c'est un constat intéressant à documenter.

Vérification d'une image :

```powershell
Get-FileHash .\SERVER_EVAL_x64FRE_fr-fr.iso -Algorithm SHA256
# comparer avec l'empreinte publiée sur la page de téléchargement
```

## 2. Réseau isolé

Dans VirtualBox, chaque VM a **une seule carte réseau** en mode
**Réseau interne**, nommé `intnet-ad`. Ce mode n'offre ni NAT, ni passerelle, ni
accès à l'hôte.

- Pas de DHCP : adresses statiques (tableau ci-dessus), masque /24, DNS = 10.10.10.10.
- Installation de Wazuh et de Kali : j'ajoute **temporairement** une seconde carte
  en NAT pour télécharger les paquets. Je la retire ensuite, avant toute attaque,
  puis je prends un snapshot.
- Les outils Windows (Sysmon, agent Wazuh, configuration SwiftOnSecurity) sont
  téléchargés sur l'hôte, vérifiés, puis copiés dans les VM via une image ISO ou
  un dossier partagé en lecture seule, désactivé après usage.

Vérification de l'isolement, depuis Kali, une fois la carte NAT retirée :

```bash
ip route                 # une seule route : 10.10.10.0/24
ping -c 2 1.1.1.1        # doit échouer
ping -c 2 10.10.10.10    # doit répondre
```

Équivalent en ligne de commande, pour une VM éteinte :

```powershell
VBoxManage modifyvm "DC01" --nic1 intnet --intnet1 "intnet-ad" --nic2 none
VBoxManage showvminfo "DC01" --machinereadable | Select-String "^nic"
# attendu : nic1="intnet", nic2="none"
```

## 3. Promotion du contrôleur de domaine (DC01)

Après installation de Windows Server, en PowerShell administrateur :

```powershell
Rename-Computer -NewName DC01 -Restart

New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.10.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1

Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "lab.internal" -DomainNetbiosName "LAB" -InstallDns
# Le mot de passe du mode restauration (DSRM) est demandé de manière interactive.
```

Pourquoi `lab.internal` : le suffixe `.internal` est réservé par l'ICANN aux
réseaux privés. Il ne peut pas entrer en collision avec un vrai domaine Internet,
contrairement à `.local` ou à un nom inventé.

Vérifications :

```powershell
Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode
dcdiag /q              # aucune erreur attendue
```

Résultat attendu : `DNSRoot = lab.internal`, `NetBIOSName = LAB`, et `dcdiag /q`
ne renvoie rien (le mode silencieux n'affiche que les erreurs).

## 4. Comptes et objets du lab

Structure d'unités d'organisation :

```text
lab.internal
├── OU=Lab
│   ├── OU=Utilisateurs   alice, bob, carol (utilisateurs standards)
│   ├── OU=Services       svc_sql, svc_backup
│   ├── OU=Admins         adm_alice (administrateur du domaine dédié)
│   └── OU=Postes         CLIENT01
└── OU=Serveurs           SRV01
```

Création des comptes (exemple, à adapter) :

```powershell
New-ADOrganizationalUnit -Name "Lab"
"Utilisateurs","Services","Admins","Postes" |
    ForEach-Object { New-ADOrganizationalUnit -Name $_ -Path "OU=Lab,DC=lab,DC=internal" }

$initialPassword = Read-Host -AsSecureString "Mot de passe initial"
New-ADUser -Name alice -SamAccountName alice -AccountPassword $initialPassword -Enabled $true `
    -Path "OU=Utilisateurs,OU=Lab,DC=lab,DC=internal"
```

## 5. Faiblesses volontaires (une par scénario)

Chaque faiblesse correspond à une erreur de configuration courante en entreprise.
Je les note ici pour que le rapport d'audit reste honnête : **elles ont été
introduites volontairement**.

| Scénario | Faiblesse introduite | Comment |
|---|---|---|
| 1 Cartographie | Rien à ajouter : tout utilisateur authentifié peut lire l'annuaire par défaut | Configuration par défaut |
| 2 Kerberoasting | `svc_sql` a un SPN, un mot de passe faible et fait partie d'un groupe privilégié | `setspn -S MSSQLSvc/srv01.lab.internal:1433 LAB\svc_sql` |
| 3 Mouvement latéral | Même mot de passe administrateur local sur SRV01 et CLIENT01, sans LAPS | Compte `localadmin` créé à l'identique |
| 4 AD CS ESC1 | Modèle de certificat `VulnUserTemplate` : le demandeur fournit le sujet, usage authentification client, inscription ouverte à « Utilisateurs du domaine » | Duplication du modèle « Utilisateur » dans `certtmpl.msc` |
| 5 DCSync | `svc_backup` reçoit les droits « Replicating Directory Changes » et « Replicating Directory Changes All » sur le domaine | Délégation sur la racine du domaine (`dsa.msc`, onglet Sécurité) |

Contrôle des faiblesses configurées :

```powershell
setspn -L LAB\svc_sql                                    # le SPN MSSQLSvc apparaît
Get-ADUser svc_sql -Properties MemberOf | Select-Object -ExpandProperty MemberOf
(Get-Acl "AD:DC=lab,DC=internal").Access |
    Where-Object IdentityReference -like "*svc_backup*"   # droits de réplication
certutil -catemplates | Select-String VulnUserTemplate    # modèle publié sur l'AC
```

Le compte leurre `svc_legacy` (scénarios 1 et 2) est créé en même temps :
description « ancien compte de sauvegarde », SPN factice
(`setspn -S HTTP/legacy-backup.lab.internal LAB\svc_legacy`), mot de passe long
et aléatoire, aucun usage réel.

## 6. Serveur membre et AD CS (SRV01)

```powershell
Rename-Computer -NewName SRV01 -Restart
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.10.20 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.10.10.10
Add-Computer -DomainName lab.internal -OUPath "OU=Serveurs,DC=lab,DC=internal" -Restart

# Avec un compte administrateur de l'entreprise :
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "LAB-CA"
```

Activer l'audit de l'autorité de certification (indispensable pour les
événements 4886 et 4887, voir [detections/README.md](../detections/README.md)) :

```powershell
certutil -setreg CA\AuditFilter 127
Restart-Service certsvc
```

## 7. Jonction du poste client (CLIENT01)

Même procédure que pour SRV01 : IP statique, DNS 10.10.10.10, puis
`Add-Computer -DomainName lab.internal -OUPath "OU=Postes,OU=Lab,DC=lab,DC=internal"`.
Je vérifie l'ouverture de session avec `LAB\alice`, puis l'application des GPO :

```powershell
gpresult /r
```

## 8. Supervision

Déploiement de Sysmon et des agents Wazuh :
[detections/README.md](../detections/README.md).

## 9. Snapshots

| Snapshot | Moment | Usage |
|---|---|---|
| `00-installe` | OS installé, mis à jour, avant le domaine | Repartir de zéro |
| `01-domaine-propre` | Domaine fonctionnel, supervision en place, **sans** faiblesse | Base saine pour vérifier les durcissements |
| `02-vulnerable` | Faiblesses du §5 configurées | Point de départ de chaque scénario |
| `03-durci-scenario-N` | Après la correction du scénario N | Preuve que l'attaque échoue |

Les snapshots des VM d'un même scénario sont pris quand elles sont **éteintes**
(ou toutes en même temps). Sinon, le canal sécurisé entre le poste et le domaine
peut se désynchroniser après une restauration. Si cela arrive :
`Test-ComputerSecureChannel -Repair`.

Prise d'un snapshot en ligne de commande (VM éteinte) :

```powershell
VBoxManage snapshot "DC01" take "02-vulnerable" --description "Faiblesses du §5 configurées"
VBoxManage snapshot "DC01" restore "02-vulnerable"
```
