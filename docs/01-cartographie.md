# Scénario 1 : cartographie de l'Active Directory

| | |
|---|---|
| **MITRE ATT&CK** | T1087.002 (Domain Account Discovery), T1069.002 (Domain Groups), T1482 (Domain Trust Discovery) |
| **Prérequis attaquant** | Un compte de domaine quelconque (ici `LAB\alice`) |
| **Outils** | [BloodHound CE / SharpHound](https://github.com/SpecterOps/BloodHound), [NetExec](https://github.com/Pennyw0rth/NetExec) |
| **Snapshot de départ** | `02-vulnerable` |

## 1. Principe

Par défaut, n'importe quel utilisateur authentifié peut lire la quasi-totalité de
l'annuaire par LDAP : utilisateurs, groupes, appartenances, ACL, SPN, délégations,
modèles de certificats. Un collecteur comme SharpHound fait ces requêtes en masse.
BloodHound les assemble ensuite en **graphe de chemins d'attaque**, par exemple :
« alice → membre de X → GenericWrite sur Y → Y est admin de SRV01 ».

Cette étape ne casse rien, mais elle conditionne toutes les suivantes. C'est
souvent la première activité anormale visible.

## 2. Observation dans le lab

Collecte depuis CLIENT01 (session `LAB\alice`) ou depuis Kali avec le collecteur
Python de BloodHound. Je suis la documentation officielle de BloodHound CE pour la
collecte et l'import.

Questions auxquelles je réponds dans BloodHound :

- Quels comptes ont un SPN (lien avec le scénario 2) ?
- Quel est le plus court chemin de `alice` vers « Admins du domaine » ?
- Qui a des droits de réplication sur le domaine (lien avec le scénario 5) ?
- Quels modèles de certificats sont vulnérables (lien avec le scénario 4) ?

TODO (captures) : graphe du plus court chemin vers « Admins du domaine ».

TODO (observation) : durée de la collecte, nombre d'objets collectés, volume
de requêtes LDAP observé.

Revue défensive de l'export : le fichier `users.json` produit par SharpHound peut
être analysé avec mon script, sans BloodHound :

```bash
python scripts/ad_triage.py bloodhound exports/users.json
```

TODO (captures) : sortie du script sur mon export.

## 3. Trace laissée dans les journaux

| Source | Événement | Ce qu'on y voit | Remarque |
|---|---|---|---|
| Security (DC) | **4662** sur un objet leurre | Lecture d'un objet qui ne devrait intéresser personne | Nécessite une SACL sur l'objet leurre (voir §4) |
| Security (postes) | **4798 / 4799** | Énumération des groupes locaux et de leurs membres (session SMB / SAMR) | Bruyant : les outils d'administration le font aussi |
| Directory Service (DC) | **1644** | Requête LDAP coûteuse ou inefficace, avec le filtre et l'IP cliente | Nécessite la journalisation « Field Engineering », plutôt pour un test ponctuel |
| Sysmon (poste) | **3** (connexion réseau) | Processus inhabituel qui se connecte au port 389 / 636 du DC | Utile si la collecte part d'un poste Windows |

TODO (observation) : événements réellement observés pendant ma collecte, et ceux
que je n'ai **pas** vus.

## 4. Règle de détection

**Approche retenue : compte leurre (honeytoken).** Je crée un compte `svc_legacy`
qui ressemble à une cible intéressante (description « ancien compte de
sauvegarde », SPN factice), mais qu'aucune application n'utilise. J'ajoute une
SACL d'audit en lecture (Everyone, « Read all properties ») sur cet objet. Toute
lecture complète de cet objet produit un 4662 : un collecteur qui aspire tout
l'annuaire le déclenche, un usage légitime jamais.

- Règle Wazuh : `100101` dans [local_rules.xml](../detections/wazuh/local_rules.xml).
- Complément : les règles `100102` (base) et `100103` (seuil) signalent un volume
  anormal de 4798/4799.

TODO (test) : vrai positif (la collecte SharpHound déclenche l'alerte) et faux
positif (une journée d'activité normale ne la déclenche pas).

## 5. Correction / durcissement

On ne peut pas empêcher un utilisateur de lire l'annuaire sans casser des
applications. L'objectif est donc de **réduire ce qui est exploitable** et de
**détecter la collecte**.

- Restreindre l'énumération SAMR à distance aux administrateurs (GPO « Accès
  réseau : restreindre les clients autorisés à effectuer des appels à distance
  vers SAM »).
- Garder les comptes leurres en place et surveiller leurs alertes.
- Corriger les chemins d'attaque révélés par BloodHound. C'est l'objet des
  scénarios suivants.
- Utiliser BloodHound **côté défense**, à intervalles réguliers, pour mesurer la
  réduction des chemins vers les comptes de niveau 0.

TODO (vérification) : capture du graphe après les corrections des scénarios 2 à 5
(chemin vers « Admins du domaine » supprimé ou allongé).

## Références

- Documentation BloodHound CE : https://bloodhound.specterops.io/
- ANSSI, « Recommandations de sécurité relatives à Active Directory ».
