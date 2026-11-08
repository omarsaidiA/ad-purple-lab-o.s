# Rapport de test d'intrusion interne : domaine `lab.internal`

| | |
|---|---|
| **Client** | Lab de référence (environnement fictif, décrit dans [docs/00-lab-setup.md](docs/00-lab-setup.md)) |
| **Type d'audit** | Test d'intrusion interne, boîte grise (compte utilisateur standard fourni) |
| **Périmètre** | Domaine Active Directory `lab.internal`, réseau 10.10.10.0/24 |
| **Auditeur** | Omar Saidi |
| **Version** | 1.0 : modèle de rapport appliqué au lab de référence |
| **Classification** | Public (aucune donnée réelle) |

> **Nature de ce document.** C'est un rapport d'audit **type**, rédigé selon les
> exigences d'un rapport de pentest professionnel et appliqué aux faiblesses
> configurées volontairement dans le lab de référence
> ([00-lab-setup.md §5](docs/00-lab-setup.md#5-faiblesses-volontaires-une-par-scénario)).
> Les constats, impacts, notations et recommandations découlent de cette
> configuration. Les **preuves de détection** sont réelles : chaque règle a été
> validée dans un manager Wazuh 4.14.5 ([detections/tests](detections/tests/)).
> Les **preuves d'exploitation** (captures) sont listées pour chaque constat :
> ce sont celles à joindre lors de l'exécution du test.

---

## 1. Synthèse managériale

Le test part d'un **compte utilisateur standard, sans privilège**, connecté au
réseau interne. Il vise à déterminer si un attaquant dans cette position (poste
compromis par hameçonnage, ou personne malveillante en interne) peut prendre le
contrôle du domaine.

**Conclusion : avec la configuration du lab, le contrôle total du domaine est
atteignable par au moins deux chemins indépendants** : un modèle de certificat
vulnérable (V-01), et un compte de service kerberoastable et privilégié (V-03).
Un troisième compte (V-02) permet ensuite d'extraire tous les secrets du
domaine.

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
4. **La journalisation par défaut ne permet pas de détecter ces attaques.** Les
   règles livrées avec ce rapport (§6) corrigent ce point.

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
approximation : la criticité retenue tient aussi compte de l'exploitabilité et
de l'impact sur le domaine.

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
  du domaine suffit, et l'impact dépasse l'AC (portée modifiée) pour toucher tout
  le domaine.
- V-02 : `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8,8) : nécessite de
  posséder le compte `svc_backup`.
- V-03 : `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8,8) : le mot de passe
  du compte est faible, donc cassable hors ligne.
- V-04 : `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7,2) : nécessite d'être
  déjà administrateur d'une machine.
- V-06 : `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4,3).

## 4. Détail des constats

Chaque constat suit le même plan : constat, preuves (exploitation à joindre et
détection validée), impact, recommandation.

### V-01 : Modèle de certificat vulnérable (ESC1)

**Criticité : Critique (9,9)** · Actif : SRV01 / LAB-CA · Write-up :
[docs/04-adcs-esc1.md](docs/04-adcs-esc1.md)

**Constat.** Le modèle `VulnUserTemplate` réunit les quatre conditions d'ESC1 :
inscription ouverte aux « Utilisateurs du domaine », pas d'approbation, usage
d'authentification client, et sujet fourni par le demandeur. N'importe quel
utilisateur peut donc obtenir un certificat valide au nom d'un administrateur
du domaine, puis s'authentifier avec.

**Preuves d'exploitation à joindre :** sortie de `certipy find` classant le
modèle en ESC1 ; certificat obtenu par `LAB\alice` avec
`SAN:upn=administrator@lab.internal` (sujet et SAN visibles, sans clé privée).

**Preuve de détection (validée) :** le 4887 correspondant déclenche la règle
**100141** (niveau 13). `ad_triage.py` produit le constat « Certificat émis pour
administrator@lab.internal à la demande de LAB\alice ».

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

**Preuves d'exploitation à joindre :** ACL de la racine du domaine listant
`svc_backup` (commande PowerShell du write-up) ; extraction du seul compte
`krbtgt`, empreintes masquées.

**Preuve de détection (validée) :** le 4662 avec le GUID
`1131f6ad-...` émis par `svc_backup` déclenche la règle **100151** (niveau 14),
alors que la même opération par un compte de DC (`DC02$`) reste au niveau 3.

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

**Preuves d'exploitation à joindre :** liste des comptes avec SPN, ticket
obtenu (tronqué), méthode et durée du cassage.

**Preuve de détection (validée) :** trois tickets RC4 demandés depuis la même IP
déclenchent la règle **100111** (niveau 12). Les tickets AES et ceux des comptes
machines ne déclenchent rien. Sur l'export BloodHound, `ad_triage.py` signale
`svc_sql` comme kerberoastable **et** privilégié (criticité haute).

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

**Preuves d'exploitation à joindre :** NetExec montrant l'accès administrateur
sur les deux machines avec la même empreinte.

**Preuve de détection (validée) :** trois connexions NTLM du même compte local
sur trois machines déclenchent **100133** ; l'exécution de type PsExec
déclenche la règle native **92650**, et celle de type wmiexec la règle **100131**.

**Impact.** Propagation rapide sur le parc, puis récupération de secrets de
comptes plus privilégiés dans la mémoire des machines atteintes.

**Recommandation.**

1. Déployer Windows LAPS sur tous les postes et serveurs.
2. Interdire la connexion réseau des comptes locaux (SID S-1-5-114).
3. Filtrer SMB et WMI entrants depuis les postes utilisateurs.

### V-05 : Journalisation insuffisante pour détecter les attaques AD

**Criticité : Moyenne (non notée en CVSS : constat organisationnel)** · Actifs :
tous · Référence : [detections/README.md](detections/README.md)

**Constat.** Avec la configuration par défaut de Windows, les attaques de ce
rapport ne produisent pas d'alerte exploitable :

- les 4769 ne sont journalisés que si l'audit Kerberos est activé ;
- aucun 4662 n'est produit sans SACL sur la racine du domaine ;
- l'AC ne produit aucun 4886/4887 tant que `CA\AuditFilter` vaut 0 ;
- la ligne de commande des processus n'est pas enregistrée ;
- il n'existe aucune règle de corrélation pour ces événements.

**Preuve.** Le banc de test montre, en plus, que les règles écrites sans le
tester échouent silencieusement : 5 erreurs ont été trouvées et corrigées
(antislashs doublés par Wazuh, `\n` littéral, classes `[...]` non comprises par
OS_Regex, deux règles natives prioritaires).

**Recommandation.** Appliquer la politique d'audit, les SACL, Sysmon et les
règles décrits dans [detections/](detections/). Garder un banc de test
automatique des règles, et vérifier chaque trimestre que chaque scénario
déclenche bien son alerte.

### V-06 : Énumération de l'annuaire par tout utilisateur

**Criticité : Faible (4,3)** · Actif : domaine · Write-up :
[docs/01-cartographie.md](docs/01-cartographie.md)

**Constat.** Comme le prévoit la configuration par défaut d'AD, tout utilisateur
authentifié peut lire l'annuaire et reconstruire les chemins d'attaque.

**Preuves d'exploitation à joindre :** graphe BloodHound du plus court chemin
de `alice` vers « Admins du domaine ».

**Preuve de détection (validée) :** la lecture du compte leurre déclenche
**100101** (niveau 12), et 20 énumérations SAMR par un même utilisateur
déclenchent **100103**.

**Recommandation.** Restreindre l'énumération SAMR à distance, déployer des
comptes leurres surveillés, et utiliser BloodHound en défense pour mesurer la
réduction des chemins d'attaque.

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

**Contre-audit.** Après remédiation, chaque scénario est rejoué depuis le
snapshot correspondant. Le résultat attendu est décrit dans la section
« Contrôle après correction » de chaque write-up :

| Constat | Correction | Résultat attendu du contre-audit |
|---|---|---|
| V-01 | Modèle corrigé, mappage fort | `certipy find` ne signale plus ESC1 ; le SAN fourni est ignoré ou la demande est mise en attente |
| V-02 | Droits retirés | L'extraction échoue (`ERROR_DS_DRA_ACCESS_DENIED`) |
| V-03 | gMSA ou mot de passe long, AES | Ticket en AES (`0x12`), cassage non réaliste ; 100110 ne se déclenche plus |
| V-04 | LAPS, GPO S-1-5-114 | Empreinte refusée sur les autres machines ; 4625 sur les cibles |
| V-05 | Audit, SACL, Sysmon, règles | Chaque scénario déclenche son alerte (banc de test 41/41) |
| V-06 | SAMR restreint, leurre | 4798/4799 refusés pour un utilisateur standard ; leurre toujours surveillé |

## 6. Détection

| Constat | Règle(s) Wazuh | Validation (Wazuh 4.14.5, banc de test) |
|---|---|---|
| V-01 | 100140, 100141 | ✅ vrai positif, SAN légitime non alerté en critique, certificat sans SAN ignoré |
| V-02 | 100150, 100151 | ✅ compte de service en niveau 14, réplication par un DC en niveau 3 |
| V-03 | 100110, 100111, 100112 | ✅ rafale RC4 détectée ; AES et comptes machines ignorés ; leurre détecté même en AES |
| V-04 | 92650 (native), 100130 à 100133 | ✅ PsExec, binaire en dossier temporaire, wmiexec, NTLM en éventail ; Sysmon64 légitime ignoré |
| V-06 | 100101, 100102, 100103 | ✅ leurre détecté ; seuil d'énumération ; comptes machines ignorés |

Banc de test : 41 événements, 41 résultats conformes. Il tourne à chaque
modification en intégration continue ([.github/workflows/ci.yml](.github/workflows/ci.yml)).

## Annexes

- A. Write-ups détaillés : [docs/](docs/)
- B. Règles de détection : [detections/wazuh/local_rules.xml](detections/wazuh/local_rules.xml)
- C. Banc de test des règles : [detections/tests/](detections/tests/)
- D. Script d'analyse et exemple de sortie : [scripts/README.md](scripts/README.md)
- E. Outils de référence : BloodHound CE, Impacket, Certipy, NetExec, Wazuh 4.14.5
