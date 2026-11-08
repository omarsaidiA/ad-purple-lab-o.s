# ad-purple-lab : attaquer, détecter et durcir un Active Directory

![CI](https://github.com/omarsaidiA/ad-purple-lab/actions/workflows/ci.yml/badge.svg)

Kit purple team pour un lab Active Directory **isolé** : cinq attaques
classiques sur AD, avec pour chacune :

1. ce que la technique exploite (principe) ;
2. comment la reproduire dans le lab, et le résultat attendu ;
3. **la trace qu'elle laisse dans les journaux** ;
4. **la règle de détection Wazuh**, testée automatiquement dans un vrai manager ;
5. **le durcissement** qui la bloque, et le contrôle qui le prouve.

L'angle est **purple team**. La partie offensive s'appuie uniquement sur des outils
publics et reconnus (voir [Outils offensifs utilisés](#outils-offensifs-utilisés)) ;
ce dépôt ne contient aucun code d'attaque. Le code fourni sert à **détecter** et
à **analyser**.

> **Ce qui est validé, ce qui ne l'est pas encore.** Les 15 règles Wazuh sont
> validées dans un manager Wazuh 4.14.5 (41 événements de test, 41 résultats
> conformes), et le script d'analyse est testé sur la sortie réelle de Wazuh.
> Le tout tourne en intégration continue. Les événements de test sont
> synthétiques : la prochaine étape est le déploiement dans le lab VirtualBox
> décrit ici, pour mesurer les vrais volumes et les vrais faux positifs (voir
> [docs/roadmap.md](docs/roadmap.md)).

---

## Architecture du lab

```text
              Réseau interne VirtualBox « intnet-ad » : 10.10.10.0/24
              (aucune route vers Internet ni vers mon réseau domestique)

  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
  │ DC01             │   │ SRV01            │   │ CLIENT01         │
  │ Windows Server   │   │ Windows Server   │   │ Windows 11       │
  │ AD DS, DNS       │   │ AD CS (AC        │   │ poste utilisateur│
  │ 10.10.10.10      │   │ entreprise),     │   │ 10.10.10.30      │
  │                  │   │ partage fichiers │   │                  │
  │ Sysmon + agent   │   │ 10.10.10.20      │   │ Sysmon + agent   │
  │ Wazuh            │   │ Sysmon + agent   │   │ Wazuh            │
  └────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘
           │                      │                      │
  ─────────┴──────────────────────┴──────────────────────┴─────────
           │                                             │
  ┌────────┴─────────┐                          ┌────────┴─────────┐
  │ KALI             │                          │ WAZUH            │
  │ poste attaquant  │                          │ manager, indexer │
  │ 10.10.10.50      │                          │ et dashboard     │
  │                  │                          │ 10.10.10.100     │
  └──────────────────┘                          └──────────────────┘

  Domaine : lab.internal (NetBIOS : LAB)
```

Le montage pas à pas est dans [docs/00-lab-setup.md](docs/00-lab-setup.md).

## Scénarios

| # | Scénario | Technique (MITRE ATT&CK) | Trace principale | Détection | Durcissement | Règles testées |
|---|---|---|---|---|---|---|
| 1 | [Cartographie de l'AD](docs/01-cartographie.md) | T1087.002, T1069.002 | Requêtes LDAP en masse, 4798/4799, compte leurre (4662) | Compte leurre + seuil d'énumération | Restreindre l'énumération SAMR, compte leurre | ✅ |
| 2 | [Kerberoasting](docs/02-kerberoasting.md) | T1558.003 | 4769 avec chiffrement RC4 (0x17) | Rafale de 4769 RC4 depuis une même IP | gMSA, AES seul, mots de passe longs | ✅ |
| 3 | [Mouvement latéral](docs/03-mouvement-lateral.md) | T1021.002, T1047, T1550.002 | 4624 type 3 NTLM, 7045, Sysmon 1 (WmiPrvSE) | Service suspect (règle native 92650 + locale), wmiexec, NTLM en éventail | Windows LAPS, pare-feu, tiering | ✅ |
| 4 | [AD CS : ESC1](docs/04-adcs-esc1.md) | T1649 | 4886/4887 avec un SAN ≠ demandeur | Certificat émis pour un autre compte | Modèle corrigé, approbation, mappage fort | ✅ |
| 5 | [DCSync](docs/05-dcsync.md) | T1003.006 | 4662 avec les GUID de réplication | Réplication par un compte non-DC | Revue des ACL du domaine, tiering | ✅ |

## Le cœur du projet : la détection

Rejouer une attaque connue ne prouve pas grand-chose. Ce qui compte en entreprise,
c'est de **savoir ce qu'elle laisse comme traces** et **comment la voir passer**.
Chaque write-up suit donc le même modèle imposé :

```text
Principe → Observation dans le lab → Trace laissée dans les logs
        → Règle de détection → Correction / durcissement
```

Chaîne de détection :

```text
Windows (journal Security + Sysmon) → agent Wazuh → manager Wazuh → règles locales
                                                       │
                                     alerts.json ──────┴──→ scripts/ad_triage.py
```

- [detections/README.md](detections/README.md) : politique d'audit, déploiement de
  Sysmon (config SwiftOnSecurity), centralisation dans Wazuh, événements par scénario.
- [detections/wazuh/local_rules.xml](detections/wazuh/local_rules.xml) : règles
  Wazuh commentées, une section par scénario.
- [detections/tests/](detections/tests/) : banc de test qui rejoue 41 événements
  Windows dans un **vrai manager Wazuh** (conteneur Docker) et vérifie la règle
  déclenchée par chacun. Il tourne en intégration continue. Il a fait apparaître
  des pièges que la documentation ne signale pas (antislashs doublés,
  expressions OS_Regex, règles natives qui masquent les règles locales), décrits
  dans [detections/README.md](detections/README.md#4-centralisation-dans-wazuh).
- [scripts/ad_triage.py](scripts/ad_triage.py) : analyse hors ligne d'un export
  Wazuh ou BloodHound, qui produit un résumé Markdown ou JSON (voir
  [scripts/README.md](scripts/README.md)).

Pour chaque règle, je cherche à mesurer :

- **le vrai positif** : l'alerte se déclenche quand je rejoue l'attaque ;
- **le faux positif** : l'alerte reste muette pendant l'activité normale du lab
  (ouverture de session, partage de fichiers, GPO) ;
- **la régression après correction** : une fois le durcissement en place, l'attaque
  échoue, et ce qu'il en reste dans les journaux est documenté.

## Rapport d'audit

[RAPPORT.md](RAPPORT.md) présente les constats sous la forme d'un rapport de test
d'intrusion professionnel : synthèse, périmètre, vulnérabilités notées en CVSS 3.1,
détail constat / preuve / recommandation, plan de remédiation.

## Compétences mises en œuvre

- **Active Directory** : AD DS, DNS, GPO, Kerberos, NTLM, ACL, AD CS (PKI d'entreprise).
- **Offensif (méthodologie)** : énumération, attaques Kerberos, abus de PKI,
  mouvement latéral, réplication d'annuaire ; cartographie MITRE ATT&CK.
- **Détection** : politique d'audit avancée, Sysmon, SIEM Wazuh, écriture et test
  de règles, réduction des faux positifs.
- **Durcissement** : Windows LAPS, gMSA, Protected Users, modèle d'administration
  en tiers, durcissement AD CS, recommandations ANSSI.
- **Analyse et automatisation** : Python (parsing JSON, tests pytest, typage mypy).
- **Restitution** : write-ups techniques, rapport d'audit avec notation CVSS.

## Suivi

- [ ] Lab monté, domaine fonctionnel, snapshots « propre » pris
- [ ] Sysmon et agents Wazuh déployés, journaux reçus sur le manager
- [ ] Scénario 1 : cartographie, détection, durcissement
- [ ] Scénario 2 : Kerberoasting, détection, durcissement
- [ ] Scénario 3 : mouvement latéral, détection, durcissement
- [ ] Scénario 4 : AD CS ESC1, détection, durcissement
- [ ] Scénario 5 : DCSync, détection, durcissement
- [ ] Export `alerts.json` analysé avec `ad_triage.py`, résultat joint aux write-ups
- [ ] Rapport d'audit complété avec mes preuves
- [x] Script d'analyse testé (pytest, ruff, mypy) en intégration continue
- [x] Règles Wazuh validées sur un vrai manager, en intégration continue

Le détail étape par étape est dans [docs/roadmap.md](docs/roadmap.md).

## Outils offensifs utilisés

Je n'écris pas d'outil d'attaque. J'utilise les projets publics de référence,
dans le lab uniquement :

| Outil | Usage dans le lab |
|---|---|
| [GOAD](https://github.com/Orange-Cyberdefense/GOAD) | Référence de lab AD vulnérable, pour comparer avec ma configuration |
| [BloodHound CE](https://github.com/SpecterOps/BloodHound) / SharpHound | Cartographie des chemins d'attaque |
| [Impacket](https://github.com/fortra/impacket) | Kerberoasting, exécution à distance, DCSync |
| [Certipy](https://github.com/ly4k/Certipy) | Audit et abus des modèles de certificats AD CS |
| [NetExec](https://github.com/Pennyw0rth/NetExec) | Énumération SMB / LDAP |

## Cadre légal

Toutes les manipulations décrites ici ont été réalisées **uniquement sur des
machines virtuelles qui m'appartiennent**, dans un réseau interne VirtualBox sans
accès à Internet ni à aucun autre réseau. Les noms, comptes et mots de passe sont
fictifs et propres au lab.

Accéder ou tenter d'accéder sans autorisation à un système d'information est un
délit (en France, articles 323-1 et suivants du Code pénal). Ce contenu a une
vocation pédagogique et défensive. Ne reproduis ces techniques que sur ton propre
lab ou dans le cadre d'une mission autorisée par écrit.

## Licence

[MIT](LICENSE)
