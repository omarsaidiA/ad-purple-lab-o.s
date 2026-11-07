# Roadmap

Progression prévue, de la base vers les scénarios avancés. Je coche une case
quand la preuve correspondante (capture, sortie, alerte) est dans le dépôt.

## Phase 0 : outillage (fait)

- [x] Structure du dépôt, modèles de write-up, rapport d'audit
- [x] Script d'analyse `ad_triage.py` testé (pytest, ruff, mypy)
- [x] Règles Wazuh validées sur un vrai manager (`detections/tests/run.sh`)
- [x] Intégration continue GitHub Actions

## Phase 1 : le lab

- [ ] Télécharger les ISO, vérifier les empreintes SHA-256
- [ ] Créer le réseau interne `intnet-ad`, vérifier l'isolement depuis Kali
- [ ] Installer DC01, promouvoir le domaine `lab.internal`, `dcdiag` sans erreur
- [ ] Créer les OU et les comptes
- [ ] Joindre SRV01 et CLIENT01 au domaine
- [ ] Installer AD CS sur SRV01, activer l'audit de l'AC
- [ ] Snapshot `01-domaine-propre`

## Phase 2 : la supervision

- [ ] Installer Wazuh (tout-en-un), retirer la carte NAT
- [ ] GPO d'audit avancée sur les DC et les membres, vérifiée avec `auditpol`
- [ ] SACL sur la racine du domaine et sur le compte leurre `svc_legacy`
- [ ] Sysmon (config SwiftOnSecurity) sur les trois machines Windows
- [ ] Agents Wazuh avec le canal Sysmon, journaux visibles dans le dashboard
- [ ] Charger `local_rules.xml`, mettre à jour le GUID du leurre (règle 100101)
- [ ] Vérifier les noms de champs réels dans une alerte du lab
- [ ] Mesurer le bruit de fond : une heure d'activité normale, alertes parasites notées

## Phase 3 : les faiblesses volontaires

- [ ] Configurer les cinq faiblesses de `00-lab-setup.md` §5, avec captures
- [ ] Snapshot `02-vulnerable`

## Phase 4 : les scénarios (un à la fois, dans cet ordre)

Pour chacun : attaque → trace → alerte → correction → attaque rejouée → échec documenté.

- [ ] 1 Cartographie : collecte BloodHound, alerte du leurre, revue `ad_triage.py bloodhound`
- [ ] 2 Kerberoasting : TGS RC4, alerte 100111, puis AES / gMSA et nouveau test
- [ ] 5 DCSync : alerte 100151, retrait des droits, échec `ERROR_DS_DRA_ACCESS_DENIED`
- [ ] 3 Mouvement latéral : psexec et wmiexec, alertes 92650 / 100131 / 100133, puis LAPS
- [ ] 4 AD CS ESC1 : alerte 100141, correction du modèle, mappage fort

(Le DCSync passe avant le mouvement latéral : même prérequis simple, et il
consolide la partie détection sur le DC.)

## Phase 5 : restitution

- [ ] Exporter `archives.json` après chaque scénario, joindre la sortie de `ad_triage.py`
- [ ] Remplir les preuves du rapport, recalculer les vecteurs CVSS
- [ ] Tableau de contre-audit (attaques rejouées après correction)
- [ ] Relire chaque write-up : aucun secret, aucune empreinte complète, IP du lab uniquement

## Pistes ensuite

- [ ] Relais NTLM (signature SMB, LDAP signing / channel binding)
- [ ] Délégation Kerberos non contrainte et contrainte
- [ ] AS-REP roasting (compte sans pré-authentification)
- [ ] Autres ESC d'AD CS (ESC4, ESC8)
- [ ] Comparer ma configuration au lab GOAD d'Orange Cyberdefense
- [ ] Règles Sigma équivalentes aux règles Wazuh, pour la portabilité
- [ ] Score PingCastle avant / après durcissement
