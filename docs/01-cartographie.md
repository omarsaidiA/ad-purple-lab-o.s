# Scénario 1 : cartographie de l'Active Directory

| | |
|---|---|
| **MITRE ATT&CK** | T1087.002 (Domain Account Discovery), T1069.002 (Domain Groups), T1482 (Domain Trust Discovery) |
| **Prérequis attaquant** | Un compte de domaine quelconque (ici `LAB\alice`) |
| **Outils** | [BloodHound CE / SharpHound](https://github.com/SpecterOps/BloodHound), [NetExec](https://github.com/Pennyw0rth/NetExec) |
| **Règles** | 100101 (compte leurre), 100102 / 100103 (énumération SAMR) |
| **Snapshot de départ** | `02-vulnerable` |

## 1. Principe

Par défaut, n'importe quel utilisateur authentifié peut lire la quasi-totalité de
l'annuaire par LDAP : utilisateurs, groupes, appartenances, ACL, SPN, délégations,
modèles de certificats. Un collecteur comme SharpHound fait ces requêtes en masse.
BloodHound les assemble ensuite en **graphe de chemins d'attaque**, par exemple :
« alice → membre de X → GenericWrite sur Y → Y est admin de SRV01 ».

Cette étape ne casse rien, mais elle conditionne toutes les suivantes. C'est
souvent la première activité anormale visible.

## 2. Reproduction et résultat attendu

**Procédure.** Collecte depuis CLIENT01 (session `LAB\alice`) avec SharpHound, ou
depuis Kali avec le collecteur Python de BloodHound, en suivant la documentation
de BloodHound CE. L'archive produite est importée dans BloodHound.

**Résultat attendu avec les faiblesses du lab** ([00-lab-setup.md §5](00-lab-setup.md#5-faiblesses-volontaires-une-par-scénario)) :

| Question posée à BloodHound | Réponse attendue | Lien |
|---|---|---|
| Quels comptes utilisateurs ont un SPN ? | `svc_sql` (et le leurre `svc_legacy`) | Scénario 2 |
| Qui peut faire un DCSync ? | `svc_backup`, en plus des DC et des administrateurs | Scénario 5 |
| Quels modèles de certificats sont vulnérables ? | `VulnUserTemplate` (ESC1) | Scénario 4 |
| Plus court chemin de `alice` vers « Admins du domaine » ? | `alice` → inscription sur `VulnUserTemplate` → certificat de l'administrateur | Scénario 4 |

**Revue défensive sans BloodHound.** Le fichier `users.json` produit par
SharpHound peut être analysé avec mon script :

```bash
python scripts/ad_triage.py bloodhound exports/users.json
```

Sortie réelle du script sur l'export de test
([tests/fixtures/bloodhound_users_sample.json](../tests/fixtures/bloodhound_users_sample.json)) :

```text
| Criticité | Scénario | Constat |
|---|---|---|
| high | Kerberoasting | 1 compte(s) utilisateur avec SPN (kerberoastable) |
| high | AS-REP roasting | 1 compte(s) sans pré-authentification Kerberos |
| medium | Hygiène des comptes | 1 compte(s) privilégié(s) avec un mot de passe ancien |
| low | Hygiène des comptes | 1 compte(s) dont le mot de passe n'expire jamais |
```

## 3. Trace laissée dans les journaux

| Source | Événement | Ce qu'on y voit | Remarque |
|---|---|---|---|
| Security (DC) | **4662** sur un objet leurre | Lecture d'un objet qui ne devrait intéresser personne | Nécessite une SACL sur l'objet leurre (voir §4) |
| Security (postes) | **4798 / 4799** | Énumération des groupes locaux et de leurs membres (SAMR) | Bruyant : les outils d'administration le font aussi |
| Directory Service (DC) | **1644** | Requête LDAP coûteuse ou inefficace, avec le filtre et l'IP cliente | Nécessite la journalisation « Field Engineering », plutôt pour un test ponctuel |
| Sysmon (poste) | **3** (connexion réseau) | Processus inhabituel qui se connecte au port 389 / 636 du DC | Utile si la collecte part d'un poste Windows |

Ce que la collecte **ne laisse pas** par défaut : une requête LDAP de lecture
n'est pas journalisée sur le DC. Sans SACL ni journalisation 1644, une collecte
BloodHound est invisible. C'est ce qui justifie le compte leurre.

**Alerte produite par Wazuh 4.14** dans le banc de test
([detections/tests](../detections/tests/)), à partir d'un événement 4662
synthétique :

```json
{
  "rule": { "id": "100101", "level": 12,
            "description": "AD lab: decoy account svc_legacy read by alice (possible AD collection)" },
  "data": { "win": {
    "system": { "eventID": "4662", "channel": "Security", "computer": "DC01.lab.internal" },
    "eventdata": { "subjectUserName": "alice",
                   "objectName": "%{00000000-0000-0000-0000-000000000000}",
                   "properties": "%%7684" } } }
}
```

## 4. Règle de détection

**Approche retenue : compte leurre (honeytoken).** Le compte `svc_legacy`
ressemble à une cible intéressante (description « ancien compte de sauvegarde »,
SPN factice), mais aucune application ne l'utilise. Une SACL d'audit en lecture
(Everyone, « Read all properties ») sur cet objet produit un 4662 à chaque
lecture complète. Un collecteur qui aspire tout l'annuaire le déclenche ; un
usage légitime, jamais.

- `100101` : lecture du leurre (niveau 12). Le GUID de l'objet se règle dans la
  règle après création du compte (`(Get-ADUser svc_legacy).ObjectGUID`).
- `100102` / `100103` : énumérations 4798 / 4799 par un compte utilisateur, puis
  20 en 2 minutes par le même compte (niveau 8).

**Validation** (banc de test, Wazuh 4.14.5) :

| Cas | Attendu | Résultat |
|---|---|---|
| 4662 sur le GUID du leurre par `alice` | 100101 | ✅ |
| 20 × 4799 par `alice` | 100102 puis 100103 au 20ᵉ | ✅ |
| 4799 par le compte machine `CLIENT01$` | aucune règle du lab | ✅ |

## 5. Correction / durcissement

On ne peut pas empêcher un utilisateur de lire l'annuaire sans casser des
applications. L'objectif est donc de **réduire ce qui est exploitable** et de
**détecter la collecte**.

- Restreindre l'énumération SAMR à distance aux administrateurs (GPO « Accès
  réseau : restreindre les clients autorisés à effectuer des appels à distance
  vers SAM »). Les 4798 / 4799 provoqués par un utilisateur standard disparaissent
  alors : l'appel est refusé.
- Garder les comptes leurres en place et surveiller leurs alertes.
- Corriger les chemins d'attaque révélés par BloodHound. C'est l'objet des
  scénarios suivants.
- Utiliser BloodHound **côté défense**, à intervalles réguliers, pour mesurer la
  réduction des chemins vers les comptes de niveau 0.

**Contrôle après correction (résultat attendu).** Après les corrections des
scénarios 2 à 5, BloodHound ne trouve plus de chemin de `alice` vers « Admins du
domaine », et le script ne signale plus de compte kerberoastable privilégié.

## Références

- Documentation BloodHound CE : https://bloodhound.specterops.io/
- ANSSI, « Recommandations de sécurité relatives à Active Directory ».
