# Scénario 4 : AD CS, ESC1

| | |
|---|---|
| **MITRE ATT&CK** | T1649 (Steal or Forge Authentication Certificates) |
| **Prérequis attaquant** | Un compte de domaine autorisé à s'inscrire au modèle vulnérable (ici `LAB\alice`) |
| **Outils** | [Certipy](https://github.com/ly4k/Certipy) (`find` pour l'audit, `req` / `auth` pour la démonstration) |
| **Faiblesse du lab** | Modèle `VulnUserTemplate` (voir [00-lab-setup.md](00-lab-setup.md#5-faiblesses-volontaires-une-par-scénario)) |
| **Règles** | 100140, 100141 + contrôle « SAN ≠ demandeur » dans `ad_triage.py` |
| **Snapshot de départ** | `02-vulnerable` |

## 1. Principe

AD CS est la PKI de Microsoft intégrée à l'AD. Un certificat dont l'usage inclut
l'**authentification client** permet d'obtenir un TGT Kerberos (PKINIT) au nom de
l'identité inscrite dans le certificat.

**ESC1** (nomenclature du livre blanc « Certified Pre-Owned », SpecterOps, 2021)
désigne un modèle qui réunit **quatre conditions** :

1. un utilisateur peu privilégié a le droit de s'inscrire ;
2. l'approbation par un gestionnaire n'est pas requise ;
3. l'usage inclut l'authentification client ;
4. **le demandeur fournit lui-même le sujet** (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
   Il peut donc écrire *n'importe quel* nom alternatif (SAN), par exemple l'UPN
   d'un administrateur du domaine.

Résultat : `alice` obtient un certificat au nom de l'administrateur, puis un TGT
de l'administrateur. C'est une élévation de privilèges directe jusqu'au domaine.

## 2. Reproduction et résultat attendu

**Procédure.**

1. **Audit** (usage défensif légitime) : `certipy find` liste les modèles de
   l'AC et signale ceux qui sont vulnérables.
2. **Démonstration** : demande d'un certificat sur `VulnUserTemplate` avec l'UPN
   de l'administrateur en SAN, puis authentification avec ce certificat, en
   suivant la documentation de Certipy.

**Résultat attendu :**

- `certipy find` classe `VulnUserTemplate` en **ESC1** : « Enrollee Supplies
  Subject » activé, « Client Authentication » présent, inscription ouverte à
  « Utilisateurs du domaine », pas d'approbation ;
- la demande aboutit : l'AC émet un certificat dont le SAN contient
  `administrator@lab.internal`, alors que le demandeur est `alice` ;
- l'authentification PKINIT avec ce certificat donne un TGT de l'administrateur ;
- avec le **mappage fort des certificats** (KB5014754) en mode « Enforcement »,
  le DC exige que le certificat contienne le SID du compte (extension SID).
  Un certificat dont le SAN pointe vers l'administrateur mais qui porte le SID
  d'`alice` (ou aucun SID) est alors refusé à l'authentification.

## 3. Trace laissée dans les journaux

| Source | Événement | Champs utiles |
|---|---|---|
| Security (AC, SRV01) | **4886** : demande de certificat reçue | `Requester`, `Attributes` (contient `SAN:upn=...`) |
| Security (AC, SRV01) | **4887** : certificat émis | `RequestId`, `Requester`, `Attributes`, `Subject` |
| Security (DC) | **4768** : TGT demandé | Champs `CertIssuerName`, `CertSerialNumber` renseignés si l'authentification utilise un certificat (PKINIT) |

Signal clé : dans un 4887, **l'UPN du SAN ne correspond pas au demandeur**
(`Requester = LAB\alice`, `SAN:upn=administrator@lab.internal`).

Prérequis : audit « Certification Services » activé **et**
`certutil -setreg CA\AuditFilter 127` sur l'AC. Sans le second, aucun 4886/4887
n'est produit.

**Alerte produite par Wazuh 4.14** dans le banc de test :

```json
{
  "rule": { "id": "100141", "level": 13,
            "description": "AD lab: certificate issued for a privileged account to LAB\\\\alice (possible ESC1)" },
  "data": { "win": {
    "system": { "eventID": "4887", "channel": "Security", "computer": "SRV01.lab.internal" },
    "eventdata": { "requestId": "12", "requester": "LAB\\\\alice",
                   "attributes": "CertificateTemplate:VulnUserTemplate\\nSAN:upn=administrator@lab.internal" } } }
}
```

Le champ `attributes` contient un attribut par ligne, mais Wazuh stocke le saut
de ligne sous la forme d'un `\n` littéral. La première version de la règle
(`(?im)^san:`) ne correspondait donc à rien : le banc de test l'a révélé.

## 4. Règle de détection

- `100140` : un 4886 ou 4887 dont les attributs contiennent un SAN (niveau 6, à
  corréler).
- `100141` : un 4887 dont le SAN pointe vers un compte privilégié
  (`administrator`, `adm_*`) (niveau 13).
- Contrôle exact (SAN ≠ demandeur) : Wazuh ne sait pas comparer deux champs dans
  une règle. Ce test est fait par `python scripts/ad_triage.py logs ...`, qui
  produit le constat :

```text
| critical | AD CS ESC1 | Certificat émis pour administrator@lab.internal à la demande de LAB\alice |
```

Fichier : [local_rules.xml](../detections/wazuh/local_rules.xml).

**Validation** (banc de test, Wazuh 4.14.5) :

| Cas | Attendu | Résultat |
|---|---|---|
| 4887 : `alice` obtient un SAN `administrator@lab.internal` | 100141 | ✅ |
| 4886 : `carol` demande un SAN à son propre nom | 100140 (niveau 6 seulement) | ✅ |
| 4887 : `bob` sur le modèle « User », sans SAN | aucune règle du lab | ✅ |

## 5. Correction / durcissement

1. **Corriger le modèle** : décocher « Fournir dans la demande » (le sujet est
   construit à partir de l'AD), ou retirer l'usage d'authentification client.
2. **Restreindre l'inscription** à un groupe dédié, pas à « Utilisateurs du
   domaine ».
3. **Exiger l'approbation d'un gestionnaire de certificats** pour tout modèle
   qui doit garder le sujet fourni.
4. **Mappage fort des certificats** (KB5014754) en mode « Enforcement » sur les DC.
5. **Audit régulier** des modèles avec `certipy find` ou `Locksmith`, et
   inventaire des modèles publiés inutilisés (à dépublier).

**Contrôle après correction (résultat attendu).** `certipy find` ne signale plus
ESC1 sur le modèle. Une demande avec un SAN arbitraire produit un certificat au
nom du demandeur (le SAN fourni est ignoré), ou reste en attente d'approbation
(4889 : demande mise en attente).

## Références

- SpecterOps, « Certified Pre-Owned: Abusing Active Directory Certificate
  Services » (2021).
- Microsoft, KB5014754 « Certificate-based authentication changes on Windows
  domain controllers ».
