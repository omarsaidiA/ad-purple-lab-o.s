# Scénario 4 : AD CS, ESC1

| | |
|---|---|
| **MITRE ATT&CK** | T1649 (Steal or Forge Authentication Certificates) |
| **Prérequis attaquant** | Un compte de domaine autorisé à s'inscrire au modèle vulnérable (ici `LAB\alice`) |
| **Outils** | [Certipy](https://github.com/ly4k/Certipy) (`find` pour l'audit, `req` / `auth` pour la démonstration) |
| **Faiblesse du lab** | Modèle `VulnUserTemplate` (voir [00-lab-setup.md](00-lab-setup.md#5-faiblesses-volontaires-une-par-scénario)) |
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

## 2. Observation dans le lab

1. **Audit** (usage défensif légitime) : `certipy find` liste les modèles et
   signale ceux qui sont vulnérables. Je compare avec la configuration attendue.
2. **Démonstration** : demande d'un certificat sur `VulnUserTemplate` avec l'UPN
   de l'administrateur en SAN, puis authentification avec ce certificat. Je suis
   la documentation de Certipy.

TODO (captures) : sortie de `certipy find` sur le modèle (section
« Vulnerabilities »), certificat obtenu (sujet et SAN visibles, **sans** la clé
privée).

TODO (observation) : comportement avec le mappage fort des certificats
(KB5014754) en mode « Enforcement » : la demande aboutit-elle encore ?
L'authentification réussit-elle ?

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

TODO (captures) : 4887 correspondant à la demande, puis 4768 avec les champs de
certificat renseignés.

## 4. Règle de détection

- `100140` : un 4886 ou 4887 dont les attributs contiennent un SAN (niveau 6, à
  corréler).
- `100141` : un 4887 sur un modèle qui autorise le sujet fourni, avec un SAN
  pointant vers un compte privilégié (niveau 13).
- Contrôle exact (SAN ≠ demandeur) : Wazuh ne sait pas comparer deux champs dans
  une règle, donc ce test est fait par
  `python scripts/ad_triage.py logs exports/alerts.json` (constat « AD CS ESC1 »).

Fichier : [local_rules.xml](../detections/wazuh/local_rules.xml).

TODO (test) : vrai positif sur ma demande, absence d'alerte pour une inscription
normale au modèle « Utilisateur ».

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

TODO (vérification) : `certipy find` ne signale plus ESC1, la même demande est
refusée ou mise en attente. Capture des deux.

## Références

- SpecterOps, « Certified Pre-Owned: Abusing Active Directory Certificate
  Services » (2021).
- Microsoft, KB5014754 « Certificate-based authentication changes on Windows
  domain controllers ».
