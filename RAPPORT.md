# Rapport de test d'intrusion interne : domaine `lab.internal`

| | |
|---|---|
| **Client** | Lab personnel (environnement fictif) |
| **Type d'audit** | Test d'intrusion interne, boîte grise (compte utilisateur standard fourni) |
| **Périmètre** | Domaine Active Directory `lab.internal`, réseau 10.10.10.0/24 |
| **Auditeur** | Omar Saidi |
| **Période** | TODO : dates de réalisation |
| **Version** | 0.1 (modèle ; preuves à compléter) |
| **Classification** | Public (aucune donnée réelle) |

> **Note :** l'environnement audité est mon propre lab. Les vulnérabilités ont été
> introduites volontairement (voir [docs/00-lab-setup.md](docs/00-lab-setup.md#5-faiblesses-volontaires-une-par-scénario)).
> Ce rapport suit néanmoins la structure et les exigences d'un rapport
> professionnel : chaque constat repose sur une preuve reproductible tirée du lab.
> Les preuves marquées TODO seront ajoutées au fil des scénarios.

---

## 1. Synthèse managériale

Le test a été mené à partir d'un **compte utilisateur standard, sans privilège**,
connecté au réseau interne. Il visait à déterminer si un attaquant dans cette
position (poste compromis par hameçonnage, ou personne malveillante en interne)
pouvait prendre le contrôle du domaine.

**Conclusion (TODO : à confirmer par les preuves) : le contrôle total du domaine
est atteignable par au moins deux chemins indépendants.**

| Criticité | Nombre |
|---|---|
| Critique | 1 |
| Élevée | 3 |
| Moyenne | 1 |
| Faible | 1 |

Principaux risques :

1. **Un modèle de certificat mal configuré (ESC1)** permet à tout utilisateur
   d'obtenir un certificat au nom d'un administrateur du domaine.
2. **Un compte de service possède des droits de réplication de l'annuaire**. S'il
   est compromis, toutes les empreintes de mots de passe du domaine peuvent être
   extraites.
3. **Des mots de passe faibles sur les comptes de service et des mots de passe
   d'administration locale identiques** facilitent la progression d'une machine
   à l'autre.
4. **La journalisation par défaut ne permettait pas de détecter ces attaques.**
   Les règles produites pendant l'audit (§6) corrigent ce point.

Priorités de remédiation : corriger le modèle de certificat et retirer les droits
de réplication **sous 48 heures**, puis déployer Windows LAPS et les gMSA (§5).

## 2. Périmètre et méthodologie

### 2.1 Périmètre

| Actif | Adresse | Rôle |
|---|---|---|
| DC01.lab.internal | 10.10.10.10 | Contrôleur de domaine, DNS |
| SRV01.lab.internal | 10.10.10.20 | Autorité de certification d'entreprise (LAB-CA), serveur de fichiers |
| CLIENT01.lab.internal | 10.10.10.30 | Poste de travail Windows 11 |

Hors périmètre : déni de service, ingénierie sociale, sécurité physique, VM de
supervision (Wazuh).

### 2.2 Conditions de départ

- Poste d'audit (Kali, 10.10.10.50) connecté au réseau interne.
- Compte fourni : `LAB\alice`, utilisateur standard.

### 2.3 Méthodologie

1. Reconnaissance et cartographie de l'annuaire (BloodHound).
2. Recherche de comptes de service exposés (Kerberoasting).
3. Revue de la PKI (Certipy).
4. Revue des ACL sensibles du domaine.
5. Mouvement latéral et élévation de privilèges.
6. Pour chaque technique : vérification de sa détection dans le SIEM.

Classification MITRE ATT&CK pour chaque constat ; notation **CVSS 3.1** (score
de base). Pour des faiblesses de configuration d'AD, le score CVSS est une
approximation : la criticité retenue tient aussi compte de l'exploitabilité
observée et de l'impact sur le domaine.

### 2.4 Échelle de criticité

| Criticité | CVSS 3.1 | Signification |
|---|---|---|
| Critique | 9,0 à 10,0 | Compromission du domaine directe et facile |
| Élevée | 7,0 à 8,9 | Compromission du domaine possible avec une étape supplémentaire |
| Moyenne | 4,0 à 6,9 | Facilite une attaque, ou défaut de détection |
| Faible | 0,1 à 3,9 | Exposition d'information, impact limité |

## 3. Tableau des vulnérabilités

| ID | Vulnérabilité | Actif | ATT&CK | CVSS 3.1 | Criticité |
|---|---|---|---|---|---|
| [V-01](#v-01--modèle-de-certificat-vulnérable-esc1) | Modèle de certificat vulnérable (ESC1) | SRV01 (LAB-CA) | T1649 | 9,9 | **Critique** |
| [V-02](#v-02--droits-de-réplication-accordés-à-un-compte-de-service-dcsync) | Droits de réplication accordés à un compte de service (DCSync) | Domaine | T1003.006 | 8,8 | **Élevée** |
| [V-03](#v-03--compte-de-service-privilégié-kerberoastable) | Compte de service privilégié kerberoastable | svc_sql | T1558.003 | 8,8 | **Élevée** |
| [V-04](#v-04--mot-de-passe-administrateur-local-partagé-sans-laps) | Mot de passe administrateur local partagé, sans LAPS | SRV01, CLIENT01 | T1550.002 | 7,2 | **Élevée** |
| [V-05](#v-05--journalisation-insuffisante-pour-détecter-les-attaques-ad) | Journalisation insuffisante pour détecter les attaques AD | Tous | - | N/A | **Moyenne** |
| [V-06](#v-06--énumération-de-lannuaire-par-tout-utilisateur) | Énumération de l'annuaire par tout utilisateur | Domaine | T1087.002 | 4,3 | **Faible** |

Vecteurs CVSS :

- V-01 : `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (9,9) : un simple compte
  du domaine suffit, et l'impact dépasse l'AC (portée modifiée) pour toucher
  tout le domaine.
- V-02 : `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8,8) : nécessite de
  posséder le compte `svc_backup`.
- V-03 : `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8,8) : nécessite que le
  mot de passe soit cassable hors ligne, ce qui a été vérifié.
- V-04 : `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7,2) : nécessite d'être
  déjà administrateur d'une machine.
- V-06 : `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4,3).

TODO : recalculer chaque vecteur avec le calculateur du FIRST une fois les
preuves réunies, et ajuster si l'exploitation réelle diffère.

## 4. Détail des constats

### V-01 : Modèle de certificat vulnérable (ESC1)

**Criticité : Critique (9,9)** · Actif : SRV01 / LAB-CA · Write-up :
[docs/04-adcs-esc1.md](docs/04-adcs-esc1.md)

**Constat.** Le modèle `VulnUserTemplate` réunit les quatre conditions d'ESC1 :
inscription ouverte aux « Utilisateurs du domaine », pas d'approbation, usage
d'authentification client, et sujet fourni par le demandeur. N'importe quel
utilisateur peut donc obtenir un certificat valide au nom d'un administrateur
du domaine, puis s'authentifier avec.

**Preuve.**

- TODO (captures) : sortie de `certipy find` signalant ESC1 sur le modèle.
- TODO (captures) : certificat obtenu par `LAB\alice` avec
  `SAN:upn=administrator@lab.internal` (sujet et SAN visibles, sans clé privée).
- TODO (captures) : événement 4887 et alerte Wazuh 100141.

**Impact.** Compromission totale du domaine depuis n'importe quel compte
utilisateur, en quelques minutes.

**Recommandation.**

1. *Immédiat* : décocher « Fournir dans la demande » sur le modèle, ou le
   dépublier s'il n'est pas utilisé.
2. Restreindre l'inscription à un groupe dédié.
3. Exiger l'approbation d'un gestionnaire de certificats pour les modèles qui
   doivent garder le sujet fourni.
4. Activer le mappage fort des certificats (KB5014754) en mode « Enforcement ».
5. Auditer les modèles chaque trimestre (Certipy `find`, Locksmith).

### V-02 : Droits de réplication accordés à un compte de service (DCSync)

**Criticité : Élevée (8,8)** · Actif : racine du domaine · Write-up :
[docs/05-dcsync.md](docs/05-dcsync.md)

**Constat.** Le compte `svc_backup` dispose des droits étendus
*DS-Replication-Get-Changes* et *DS-Replication-Get-Changes-All* sur la racine
du domaine. Ces droits suffisent pour demander à un DC les secrets de
n'importe quel compte, y compris `krbtgt`.

**Preuve.**

- TODO (captures) : ACL de la racine du domaine montrant `svc_backup`.
- TODO (captures) : extraction de l'empreinte de `krbtgt` (empreinte masquée).
- TODO (captures) : événement 4662 et alerte Wazuh 100151.

**Impact.** Extraction de toutes les empreintes du domaine, persistance par
Golden Ticket.

**Recommandation.**

1. *Immédiat* : retirer les droits de réplication à `svc_backup`.
2. Contrôler les ACL de la racine du domaine chaque mois (script PowerShell du
   write-up, BloodHound ou PingCastle).
3. Traiter tout compte qui conserve ces droits comme un compte de niveau 0.

### V-03 : Compte de service privilégié kerberoastable

**Criticité : Élevée (8,8)** · Actif : `svc_sql` · Write-up :
[docs/02-kerberoasting.md](docs/02-kerberoasting.md)

**Constat.** Le compte `svc_sql` porte un SPN, accepte le chiffrement RC4, a un
mot de passe faible et appartient à un groupe privilégié. Tout utilisateur peut
obtenir un ticket de service pour ce compte et casser son mot de passe hors
ligne.

**Preuve.**

- TODO (captures) : liste des comptes avec SPN, ticket obtenu (empreinte tronquée).
- TODO (observation) : temps de cassage et méthode (petite liste de mots).
- TODO (captures) : événements 4769 en RC4 et alerte Wazuh 100111.

**Impact.** Prise de contrôle d'un compte privilégié, puis du domaine.

**Recommandation.**

1. Migrer `svc_sql` vers un gMSA ; à défaut, un mot de passe aléatoire de 25
   caractères ou plus.
2. Forcer AES (`msDS-SupportedEncryptionTypes = 0x18`), puis désactiver RC4 au
   niveau du domaine.
3. Retirer le compte des groupes privilégiés.

### V-04 : Mot de passe administrateur local partagé, sans LAPS

**Criticité : Élevée (7,2)** · Actifs : SRV01, CLIENT01 · Write-up :
[docs/03-mouvement-lateral.md](docs/03-mouvement-lateral.md)

**Constat.** Le compte administrateur local `localadmin` a le même mot de passe
sur SRV01 et CLIENT01. L'empreinte NTLM récupérée sur une machine donne un accès
administrateur à l'autre (pass-the-hash).

**Preuve.**

- TODO (captures) : NetExec montrant l'accès administrateur sur les deux machines.
- TODO (captures) : événements 4624 NTLM et 7045, alertes Wazuh 100133 et 92650.

**Impact.** Propagation rapide sur le parc, puis récupération de secrets de
comptes plus privilégiés dans la mémoire des machines atteintes.

**Recommandation.**

1. Déployer Windows LAPS sur tous les postes et serveurs.
2. Interdire la connexion réseau des comptes locaux (SID S-1-5-114).
3. Filtrer SMB et WMI entrants depuis les postes utilisateurs.

### V-05 : Journalisation insuffisante pour détecter les attaques AD

**Criticité : Moyenne (non notée en CVSS : constat organisationnel)** · Actifs :
tous · Référence : [detections/README.md](detections/README.md)

**Constat.** Avec la configuration par défaut, aucune des attaques de ce rapport
ne produisait d'alerte exploitable. Les événements 4662 et 4886/4887 n'étaient
pas générés, la ligne de commande des processus n'était pas journalisée, et
aucune règle de corrélation n'existait.

**Preuve.**

- TODO (observation) : tentative de détection avant / après la mise en place de
  la politique d'audit et des règles.

**Recommandation.** Appliquer la politique d'audit, les SACL, Sysmon et les
règles décrits dans [detections/](detections/), et vérifier chaque trimestre que
chaque scénario déclenche bien son alerte.

### V-06 : Énumération de l'annuaire par tout utilisateur

**Criticité : Faible (4,3)** · Actif : domaine · Write-up :
[docs/01-cartographie.md](docs/01-cartographie.md)

**Constat.** Comme le prévoit la configuration par défaut d'AD, tout utilisateur
authentifié peut lire l'annuaire et reconstruire les chemins d'attaque.

**Preuve.** TODO (captures) : graphe BloodHound du plus court chemin vers
« Admins du domaine ».

**Recommandation.** Restreindre l'énumération SAMR à distance, déployer des
comptes leurres surveillés (règle 100101), et utiliser BloodHound en défense
pour mesurer la réduction des chemins d'attaque.

## 5. Plan de remédiation

| Priorité | Échéance | Action | Constats | Effort |
|---|---|---|---|---|
| P0 | 48 h | Corriger ou dépublier `VulnUserTemplate` | V-01 | Faible |
| P0 | 48 h | Retirer les droits de réplication de `svc_backup` | V-02 | Faible |
| P1 | 2 semaines | Changer le mot de passe de `svc_sql`, le retirer des groupes privilégiés, forcer AES | V-03 | Faible |
| P1 | 2 semaines | Déployer Windows LAPS, interdire la connexion réseau des comptes locaux | V-04 | Moyen |
| P1 | 2 semaines | Politique d'audit, SACL, Sysmon, règles Wazuh | V-05 | Moyen |
| P2 | 3 mois | Migrer les comptes de service vers des gMSA | V-03 | Moyen |
| P2 | 3 mois | Mappage fort des certificats en mode « Enforcement » | V-01 | Moyen |
| P2 | 3 mois | Modèle d'administration en tiers, postes d'administration dédiés | V-02, V-04 | Élevé |
| P3 | Continu | Revue trimestrielle : BloodHound, Certipy, ACL du domaine, test des alertes | Tous | Faible |

**Vérification.** Après remédiation, chaque scénario est rejoué depuis le
snapshot correspondant. L'échec de l'attaque et la trace laissée sont
documentés dans le write-up (section « Correction / durcissement »).

TODO : tableau de contre-audit (constat, date de correction, attaque rejouée,
résultat).

## 6. Détection

| Constat | Règle(s) Wazuh | Testée en CI | Vrai positif dans le lab | Faux positifs observés |
|---|---|---|---|---|
| V-01 | 100140, 100141 | ✅ | TODO | TODO |
| V-02 | 100150, 100151 | ✅ | TODO | TODO |
| V-03 | 100110, 100111, 100112 | ✅ | TODO | TODO |
| V-04 | 92650 (native), 100130 à 100133 | ✅ | TODO | TODO |
| V-06 | 100101, 100102, 100103 | ✅ | TODO | TODO |

« Testée en CI » : la logique de la règle est validée sur des événements
synthétiques dans un vrai manager Wazuh (`detections/tests/run.sh`). Les deux
colonnes suivantes seront remplies avec les résultats obtenus dans le lab.

## Annexes

- A. Write-ups détaillés : [docs/](docs/)
- B. Règles de détection : [detections/wazuh/local_rules.xml](detections/wazuh/local_rules.xml)
- C. Sortie de `scripts/ad_triage.py` sur l'export du lab : TODO
- D. Outils utilisés : BloodHound CE, Impacket, Certipy, NetExec (versions : TODO)
