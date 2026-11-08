# scripts/ad_triage.py

Outil d'**analyse défensive** hors ligne. Il lit des fichiers déjà exportés du lab
et ne se connecte à rien : ni au réseau, ni à un contrôleur de domaine. Il
n'utilise que la bibliothèque standard de Python (3.10 ou plus récent).

## Commandes

### `logs` : triage d'un export Wazuh

```bash
python scripts/ad_triage.py logs exports/archives.json
python scripts/ad_triage.py logs exports/alerts.json --format json > triage.json
```

Entrée : un document JSON par ligne, au format de `alerts.json` ou
`archives.json` de Wazuh (`/var/ossec/logs/alerts/` et `/var/ossec/logs/archives/`).
Un événement Windows brut (`{"win": {...}}`) est aussi accepté. Les lignes qui ne
sont pas des événements Windows sont comptées, puis ignorées.

L'outil annule l'échappement appliqué par Wazuh (antislashs doublés, `\n`
littéraux, entités XML) avant l'analyse.

| Constat | Événements | Logique | Option |
|---|---|---|---|
| Kerberoasting | 4769 | TGS en RC4 (0x17 / 0x18) pour un compte utilisateur, regroupés par IP source ; criticité haute à partir du seuil | `--kerberoast-threshold` (3) |
| DCSync | 4662 | GUID de réplication exercé par un compte qui ne finit pas par `$` | - |
| AD CS ESC1 | 4887 | UPN du SAN ≠ compte demandeur | - |
| Mouvement latéral | 7045 | Binaire de service dans `%SystemRoot%\<nom>.exe` ou un dossier temporaire | - |
| Mouvement latéral | Sysmon 1 | Ligne de commande avec sortie vers `\\127.0.0.1\ADMIN$\__<n>` (wmiexec) | - |
| Mouvement latéral | 4624 | Même compte, type 3, NTLM, sur plusieurs machines | `--lateral-threshold` (3) |
| Cartographie | 4798 / 4799 | Énumérations en masse par un compte utilisateur | `--enumeration-threshold` (20) |

Le script complète les règles Wazuh : il fait les comparaisons entre champs que
Wazuh ne sait pas faire (SAN ≠ demandeur) et produit un résumé à joindre aux
write-ups.

### `bloodhound` : revue des comptes

```bash
python scripts/ad_triage.py bloodhound exports/users.json
```

Entrée : le fichier `*_users.json` produit par SharpHound (BloodHound CE). Le
script ignore les comptes désactivés et `krbtgt`, puis signale :

- les comptes **kerberoastables** (SPN sur un compte utilisateur), en criticité
  haute si l'un d'eux est privilégié (`admincount`) ;
- les comptes **AS-REP roastables** (pré-authentification Kerberos désactivée) ;
- les comptes privilégiés dont le **mot de passe est ancien**
  (`--password-age-days`, 365 par défaut) ;
- les mots de passe qui **n'expirent jamais**.

## Exemple de sortie

Sur l'export Wazuh des tests (`tests/fixtures/wazuh_archives_sample.jsonl`) :

```text
| Criticité | Scénario | Constat |
|---|---|---|
| critical | AD CS ESC1 | Certificat émis pour administrator@lab.internal à la demande de LAB\alice |
| critical | DCSync | Réplication d'annuaire demandée par le compte non-DC LAB\svc_backup |
| high | Kerberoasting | 3 ticket(s) de service RC4 demandé(s) depuis 10.10.10.50 : rafale typique d'un Kerberoasting |
| high | Mouvement latéral | Service suspect installé sur SRV01.lab.internal : BTOBTO |
...
```

Sur un export réel, la commande est la même : copier `archives.json` du manager
(avec `logall_json` activé) puis lancer le script dessus.

## Tests

```bash
pip install pytest ruff mypy
python -m pytest        # tests/test_ad_triage.py
ruff check . && mypy
```

La fixture `wazuh_archives_sample.jsonl` est une **vraie sortie de Wazuh 4.14** :
les événements synthétiques de `detections/tests/cases.py` passés dans un
manager Wazuh par `detections/tests/run.sh`. Le parsing est donc testé sur le
format réel, échappement compris. Pour la régénérer :

```bash
detections/tests/run.sh tests/fixtures/wazuh_archives_sample.jsonl
```

## Ce que l'outil ne fait pas

- Il ne lit pas les fichiers `.evtx` directement. Il faut passer par Wazuh, ou
  convertir l'export au format `{"win": {"system": ..., "eventdata": ...}}`.
- Il n'agit pas sur l'AD : il n'a aucune fonction offensive ni corrective.
- Les seuils sont des points de départ, à ajuster selon les faux positifs
  mesurés dans le lab.
