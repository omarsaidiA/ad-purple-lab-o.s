# Scénario 5 : DCSync

| | |
|---|---|
| **MITRE ATT&CK** | T1003.006 (OS Credential Dumping: DCSync) |
| **Prérequis attaquant** | Un compte avec les droits de réplication sur le domaine (ici `LAB\svc_backup`) |
| **Outils** | [Impacket](https://github.com/fortra/impacket) (`secretsdump.py`) |
| **Faiblesse du lab** | `svc_backup` a reçu « Replicating Directory Changes » et « Replicating Directory Changes All » |
| **Règles** | 100150, 100151 |
| **Snapshot de départ** | `02-vulnerable` |

## 1. Principe

Les contrôleurs de domaine se répliquent entre eux avec le protocole **MS-DRSR**
(fonction `DRSGetNCChanges`). Le DC qui reçoit la demande ne vérifie pas que le
demandeur est un DC : il vérifie seulement **deux droits étendus** sur la racine
du domaine :

| Droit | GUID |
|---|---|
| DS-Replication-Get-Changes | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-All | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-In-Filtered-Set | `89e95b76-444d-4c62-991a-0facbeda640c` |

Un compte qui possède ces droits peut donc se faire passer pour un DC et
récupérer les secrets de n'importe quel compte, y compris l'empreinte de
`krbtgt`. Cela suffit à forger des Golden Tickets et à compromettre durablement
le domaine.

En entreprise, ces droits finissent souvent sur un compte de service par erreur :
outil de synchronisation, de sauvegarde ou d'audit configuré « pour que ça
marche ».

## 2. Reproduction et résultat attendu

**Procédure.**

1. **Constat côté défense** : qui possède ces droits ? BloodHound (arête
   `DCSync`) ou PowerShell :

   ```powershell
   (Get-Acl "AD:DC=lab,DC=internal").Access |
       Where-Object { $_.ObjectType -in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |
       Select-Object IdentityReference, ObjectType, ActiveDirectoryRights
   ```

2. **Démonstration** : avec `svc_backup`, extraction du **seul compte `krbtgt`**
   avec `secretsdump.py` (option `-just-dc-user`, voir la documentation
   d'Impacket). Inutile de récupérer toute la base : cela suffit à prouver le
   risque.

**Résultat attendu :**

- la commande PowerShell liste `LAB\svc_backup` à côté des groupes légitimes
  (« Contrôleurs de domaine de l'entreprise », « Administrateurs ») ;
- l'extraction renvoie les empreintes de `krbtgt`. Elles ne sont jamais publiées,
  même tronquées.

## 3. Trace laissée dans les journaux

| Source | Événement | Ce qu'on y voit |
|---|---|---|
| Security (DC) | **4662** : opération sur un objet | `Properties` contient l'un des GUID ci-dessus, `SubjectUserName` = le compte demandeur |
| Security (DC) | **4624** type 3 | Connexion réseau du compte depuis l'IP de Kali, juste avant |

Signal clé : un 4662 avec un GUID de réplication dont le `SubjectUserName`
**ne se termine pas par `$`**. Les DC répliquent avec leur compte machine ; un
compte utilisateur qui réplique est anormal.

Prérequis : audit « Directory Service Access » en succès sur les DC **et** une
entrée SACL d'audit sur la racine du domaine (Everyone, droits étendus de
réplication). Voir [detections/README.md](../detections/README.md).

Côté réseau : un trafic DRSUAPI (RPC) vers un DC depuis une IP qui n'est pas un DC.
C'est aussi détectable par un IDS, en dehors du périmètre de ce lab.

**Alerte produite par Wazuh 4.14** dans le banc de test :

```json
{
  "rule": { "id": "100151", "level": 14,
            "description": "AD lab: directory replication requested by non-DC account svc_backup (possible DCSync)" },
  "data": { "win": {
    "system": { "eventID": "4662", "channel": "Security", "computer": "DC01.lab.internal" },
    "eventdata": { "subjectUserName": "svc_backup", "subjectDomainName": "LAB",
                   "objectName": "%{11111111-2222-3333-4444-555555555555}",
                   "properties": "%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}" } } }
}
```

## 4. Règle de détection

- `100150` : 4662 contenant un GUID de réplication (niveau 3, base).
- `100151` : même événement avec un `subjectUserName` qui ne finit pas par `$`
  (niveau 14 : critique).
- Analyse hors ligne : constat « DCSync » de
  `python scripts/ad_triage.py logs exports/archives.json`.

Fichier : [local_rules.xml](../detections/wazuh/local_rules.xml).

**Validation** (banc de test, Wazuh 4.14.5) :

| Cas | Attendu | Résultat |
|---|---|---|
| 4662, GUID `...-Get-Changes-All`, compte `svc_backup` | 100151 | ✅ |
| 4662, même GUID, compte machine `DC02$` (réplication normale) | 100150 (niveau 3 seulement) | ✅ |

**Faux positif connu :** Microsoft Entra Connect utilise un compte `MSOL_*` qui
possède légitimement ces droits. S'il est présent, il est ajouté en exception
**nominative** (jamais par motif générique).

## 5. Correction / durcissement

1. **Retirer les droits de réplication** à tout compte qui n'est pas un DC (ou un
   outil explicitement justifié et documenté).
2. **Contrôle périodique** des ACL de la racine du domaine (script du §2,
   BloodHound, PingCastle).
3. **Modèle en tiers** : les comptes qui gardent ces droits sont des comptes de
   niveau 0, protégés comme des administrateurs du domaine (groupe Protected
   Users, connexion uniquement depuis des postes d'administration).
4. **Après une compromission** : réinitialiser deux fois le mot de passe de
   `krbtgt` (en respectant le délai de réplication), pour invalider les tickets
   forgés.

**Contrôle après correction (résultat attendu).** `svc_backup` n'apparaît plus
dans la sortie PowerShell du §2. La même extraction échoue avec une erreur
d'accès refusé du DC (`ERROR_DS_DRA_ACCESS_DENIED`).

## Références

- Microsoft, spécification MS-DRSR.
- ANSSI, point de contrôle « Droits de réplication accordés à des comptes non
  DC » (référentiel ADS).
