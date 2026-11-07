# Détection : politique d'audit, Sysmon et Wazuh

Pour détecter une attaque sur AD, il faut d'abord **produire les bons journaux**.
La configuration par défaut de Windows n'enregistre pas la plupart des
événements utiles (4769 détaillés, 4662, 4886/4887, lignes de commande). Ce
document décrit, dans l'ordre :

1. la politique d'audit à appliquer par GPO ;
2. les SACL sans lesquelles certains événements n'existent pas ;
3. le déploiement de Sysmon ;
4. la centralisation dans Wazuh ;
5. les événements et règles par scénario ;
6. la méthode de test d'une règle.

## 1. Politique d'audit avancée (GPO)

GPO `LAB - Audit DC` liée à l'OU *Domain Controllers*, et `LAB - Audit membres`
liée à `OU=Lab` et `OU=Serveurs`. Chemin :
*Configuration ordinateur → Stratégies → Paramètres Windows → Paramètres de
sécurité → Configuration avancée de la stratégie d'audit*.

| Catégorie | Sous-catégorie | Réglage | Événements | Scénarios | GPO |
|---|---|---|---|---|---|
| Connexion de compte | Audit du service d'authentification Kerberos | Succès, Échec | 4768, 4771 | 4 | DC |
| Connexion de compte | Audit des opérations de ticket du service Kerberos | Succès, Échec | **4769** | 2 | DC |
| Accès DS | Audit de l'accès au service d'annuaire | Succès | **4662** | 1, 5 | DC |
| Ouverture/fermeture de session | Audit de l'ouverture de session | Succès, Échec | **4624**, 4625 | 3 | les deux |
| Ouverture/fermeture de session | Audit de l'ouverture de session spéciale | Succès | 4672 | 3 | les deux |
| Accès à l'objet | Audit des services de certification | Succès, Échec | **4886, 4887** | 4 | membres (AC) |
| Accès à l'objet | Audit du partage de fichiers détaillé | Succès, Échec | 5145 | 3 | membres |
| Gestion des comptes | Audit de la gestion des groupes de sécurité | Succès | **4799**, 4728, 4732 | 1 | les deux |
| Gestion des comptes | Audit de la gestion des comptes d'utilisateur | Succès | **4798**, 4720, 4738 | 1 | les deux |
| Suivi détaillé | Audit de la création du processus | Succès | 4688 | 3 | les deux |
| Système | Audit de l'extension système de sécurité | Succès | 4697 | 3 | les deux |

À activer en plus :

- *Modèles d'administration → Système → Audit de la création de processus →
  Inclure la ligne de commande dans les événements de création de processus*
  (sinon les 4688 sont presque inutiles) ;
- *Options de sécurité → Audit : forcer les paramètres de sous-catégorie de
  stratégie d'audit* = Activé ;
- taille du journal Security sur les DC : au moins 1 Go, pour ne pas perdre
  l'historique entre deux collectes.

Vérification sur chaque machine :

```powershell
gpupdate /force
auditpol /get /category:*
```

TODO (captures) : sortie d'`auditpol` sur DC01.

**Côté autorité de certification (SRV01)**, la GPO ne suffit pas : il faut aussi
activer l'audit de l'AC elle-même.

```powershell
certutil -setreg CA\AuditFilter 127
Restart-Service certsvc
```

## 2. SACL nécessaires

L'événement 4662 n'est produit que si l'objet concerné porte une **SACL**
(entrée d'audit) correspondante.

**Racine du domaine (scénario 5, DCSync)** : auditer l'usage des droits étendus
de réplication par tout le monde.

```powershell
Import-Module ActiveDirectory
$path = "AD:DC=lab,DC=internal"
$acl = Get-Acl -Path $path -Audit
$everyone = [System.Security.Principal.SecurityIdentifier]"S-1-1-0"
foreach ($guid in "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",   # Get-Changes
                  "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",   # Get-Changes-All
                  "89e95b76-444d-4c62-991a-0facbeda640c") { # Get-Changes-In-Filtered-Set
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
        $everyone, "ExtendedRight", "Success", [guid]$guid)
    $acl.AddAuditRule($rule)
}
Set-Acl -Path $path -AclObject $acl
```

**Compte leurre `svc_legacy` (scénarios 1 et 2)** : auditer toute lecture de ses
propriétés.

```powershell
$path = "AD:" + (Get-ADUser svc_legacy).DistinguishedName
$acl = Get-Acl -Path $path -Audit
$rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $everyone, "ReadProperty", "Success")
$acl.AddAuditRule($rule)
Set-Acl -Path $path -AclObject $acl

(Get-ADUser svc_legacy -Properties ObjectGUID).ObjectGUID   # à reporter dans la règle 100101
```

## 3. Sysmon

Sysmon (Sysinternals) enrichit la télémétrie : création de processus avec parent
et ligne de commande complète (événement 1), connexions réseau (3), création de
fichiers (11), etc.

Configuration utilisée : **SwiftOnSecurity sysmon-config**
(<https://github.com/SwiftOnSecurity/sysmon-config>, fichier
`sysmonconfig-export.xml`). C'est une base commentée qui filtre le bruit
habituel. Alternative plus modulaire : `olafhartong/sysmon-modular`.

Installation sur DC01, SRV01 et CLIENT01 (fichiers apportés dans la VM comme
décrit dans [00-lab-setup.md](../docs/00-lab-setup.md#2-réseau-isolé)) :

```powershell
# Vérifier la signature du binaire avant de l'exécuter
Get-AuthenticodeSignature .\Sysmon64.exe

.\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml

# Mise à jour ultérieure de la configuration
.\Sysmon64.exe -c .\sysmonconfig-export.xml

# Vérification
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Limites de la configuration SwiftOnSecurity à connaître :

- les connexions réseau (événement 3) ne sont journalisées que pour une liste de
  processus. Une collecte LDAP par un binaire inconnu peut donc passer inaperçue ;
  je l'ajoute si besoin dans une configuration locale dérivée, versionnée ici ;
- la configuration est un point de départ, pas une garantie : chaque
  modification est documentée dans le write-up concerné.

TODO (observation) : modifications apportées à la configuration, et pourquoi.

## 4. Centralisation dans Wazuh

### Serveur (VM WAZUH)

Installation tout-en-un (manager, indexer, dashboard) avec l'assistant officiel,
pendant que la carte NAT temporaire est présente. Je suis la documentation
« Quickstart » de Wazuh pour la version courante, puis je retire la carte NAT.

TODO (captures) : version de Wazuh installée, dashboard accessible depuis Kali
sur `https://10.10.10.100`.

### Agents Windows

```powershell
msiexec.exe /i wazuh-agent-<version>-1.msi /q WAZUH_MANAGER="10.10.10.100" `
    WAZUH_AGENT_NAME="DC01"
NET START WazuhSvc
```

Par défaut, l'agent collecte les journaux Application, Security et System. Il
faut ajouter Sysmon (et, pour le scénario 1, Directory Service) dans
`C:\Program Files (x86)\ossec-agent\ossec.conf`. Voir
[wazuh/agent-ossec-snippet.xml](wazuh/agent-ossec-snippet.xml). Les règles Sysmon
fournies avec Wazuh décodent ensuite ces événements sous le préfixe
`win.eventdata.*`.

### Règles locales

Les règles de ce dépôt se trouvent dans
[wazuh/local_rules.xml](wazuh/local_rules.xml). Sur le manager :

```bash
sudo cp local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t        # vérifie la syntaxe
sudo systemctl restart wazuh-manager
```

Points appris en testant les règles contre un vrai manager Wazuh (voir §7) :

- **Noms de champs** : le décodeur Windows met la première lettre en minuscule
  (`TicketEncryptionType` devient `win.eventdata.ticketEncryptionType`).
- **Antislashs doublés** : dans les champs décodés, `C:\Windows\Temp` devient
  `C:\\Windows\\Temp`. Les règles utilisent donc `\\+` (un antislash ou plus).
  La règle native 92650 de Wazuh fait la même hypothèse.
- **Retours à la ligne** : un champ multi-ligne (les attributs d'un 4887)
  contient un `\n` littéral, pas un vrai saut de ligne.
- **Syntaxe des expressions** : sans `type="pcre2"`, Wazuh utilise OS_Regex, qui
  ne connaît pas les classes `[...]`. `^479[89]$` ne correspond donc à rien ;
  il faut écrire `^4798$|^4799$`.
- **Ordre d'évaluation** : parmi les règles filles, la première qui correspond
  l'emporte. Une règle native de niveau 0 peut ainsi masquer une règle locale.
  C'est le cas de 92069 pour les processus lancés par WMI ; 100131 est donc
  déclarée comme sa fille (`if_sid`).

## 5. Événements à surveiller par scénario

| Scénario | Événement | Condition suspecte | Règle Wazuh | Script |
|---|---|---|---|---|
| 1 Cartographie | 4662 (DC) | Lecture de l'objet leurre `svc_legacy` | 100101 | - |
| 1 Cartographie | 4798 / 4799 | Volume élevé par un même compte | 100102, 100103 | `Cartographie` |
| 2 Kerberoasting | 4769 (DC) | `ticketEncryptionType` 0x17 / 0x18, service utilisateur | 100110, 100111 | `Kerberoasting` |
| 2 Kerberoasting | 4769 (DC) | Ticket demandé pour le leurre `svc_legacy` | 100112 | - |
| 3 Mouvement latéral | 7045 (System) | Binaire de service à la racine de `%SystemRoot%` | 92650 (native) | `Mouvement latéral` |
| 3 Mouvement latéral | 7045 (System) | Binaire de service dans un dossier temporaire | 100130 | `Mouvement latéral` |
| 3 Mouvement latéral | Sysmon 1 | Parent `WmiPrvSE.exe` + sortie vers `\\127.0.0.1\ADMIN$\__` | 100131 | `Mouvement latéral` |
| 3 Mouvement latéral | 4624 | Type 3, NTLM, compte non-machine, plusieurs machines | 100132, 100133 | `Mouvement latéral` |
| 4 AD CS ESC1 | 4886 / 4887 (AC) | Attributs avec un SAN | 100140 | - |
| 4 AD CS ESC1 | 4887 (AC) | SAN = compte privilégié, ou SAN ≠ demandeur | 100141 | `AD CS ESC1` |
| 5 DCSync | 4662 (DC) | GUID de réplication, demandeur sans `$` | 100150, 100151 | `DCSync` |

La colonne « Script » donne le nom du constat produit par
[scripts/ad_triage.py](../scripts/ad_triage.py) sur un export `alerts.json` ou
`archives.json`.

> **Pourquoi deux outils ?** Les règles Wazuh détectent en temps réel. Le script
> sert à l'analyse après coup, et fait des comparaisons qu'une règle Wazuh ne
> sait pas faire (par exemple : SAN ≠ demandeur). Il permet aussi de tester la
> logique de détection avec pytest, sans lab allumé.

## 6. Méthode de test d'une règle

Pour chaque règle, je note dans le write-up :

1. **Vrai positif** : je rejoue l'attaque, l'alerte apparaît (capture du
   dashboard avec l'ID de règle).
2. **Faux positifs** : j'utilise le lab normalement pendant une période définie
   (connexions, partages, GPO, inscription de certificats légitime) et je compte
   les alertes parasites.
3. **Ajustement** : seuil, liste d'exceptions nominative, ou règle abandonnée si
   elle est trop bruyante. Chaque choix est justifié.
4. **Après durcissement** : l'attaque échoue. Je documente ce qui reste visible
   (souvent des échecs : 4625, 4768 en échec, refus de l'AC).

Pour l'analyse hors ligne, j'active `logall_json` sur le manager pendant les
tests, afin d'avoir **tous** les événements dans `archives.json`, y compris ceux
qui n'ont déclenché aucune règle. Je le désactive ensuite (volume important).

## 7. Tests automatiques des règles

Avant de déployer une règle dans le lab, je vérifie sa logique sans VM Windows :
[tests/run.sh](tests/run.sh) démarre un conteneur `wazuh/wazuh-manager`
jetable et y charge `local_rules.xml`. Il injecte ensuite les événements de
[tests/cases.py](tests/cases.py) **au format envoyé par l'agent Windows** (XML
de l'événement), pour qu'ils passent par le vrai décodeur et tout le jeu de
règles. Enfin, il compare la règle déclenchée par chaque événement à la règle
attendue.

```bash
detections/tests/run.sh            # Docker et Python 3 requis
# ...
# 41/41 cases passed
```

Chaque règle a au moins un cas positif, et les cas négatifs couvrent les pièges
connus : compte machine, ticket AES, service légitime dans `C:\Windows`, SAN
égal au demandeur. Les tests tournent aussi en intégration continue.

Ces tests valident la **logique** des règles sur des événements synthétiques.
Ils ne remplacent pas le test dans le lab (§6), qui seul montre les vrais
champs, le vrai volume et les vrais faux positifs.
