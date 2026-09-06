# dpi-probe

[English](README.md) | [Français](README.fr.md) | [Русский](README.ru.md) | [简体中文](README.zh.md)

**1.0.0-beta.1** est une batterie de diagnostic réseau en terminal : anomalies DNS, TCP, TLS/SNI, HTTP Host, ECH, resets, segmentation et comparaison de chemins. VLESS/REALITY est un module spécialisé parmi ces fonctions.

L'objectif est de comprendre à quelle étape une connexion échoue, de rassembler des preuves et de proposer les vérifications suivantes. Un timeout ne prouve pas un DPI. Un RST n'identifie pas son auteur. Deux captures peuvent borner une différence entre points d'observation, sans désigner le routeur responsable.

## Ce que cela apporte

| Situation | Utilité |
|---|---|
| Un service fonctionne en mobile mais pas à domicile | Comparer DNS, TCP et TLS avec la même cible et les mêmes paramètres. |
| Suspicion de DNS poisoning | Comparer réponses locales et références, en conservant les alternatives CDN, panne ou référence inaccessible. |
| TCP fonctionne, mais TLS reste sans réponse | Faire varier SNI, champs TLS et segmentation des écritures TCP ; observer les réponses. |
| Vérifier ECH | Séparer publication DNS HTTPS et requête réelle exigeant ECH avec un curl compatible. |
| Coupures, resets ou transfert asymétrique | Examiner les séquences, acquittements et l'ordre FIN/RST dans les captures client/serveur. |
| Échec VLESS/REALITY | Croiser configuration sing-box, logs, route et captures ; exposer phase observée, causes possibles et preuves manquantes. |

## Installation

Télécharger et extraire le dépôt. Sous Windows, ouvrir **`dpi-probe.cmd`**. Sous Linux, lancer **`sh dpi-probe.sh`** dans son dossier.

Le lanceur vérifie Python 3.11+, propose de créer `.venv` et d'y installer `requirements.txt`, puis contrôle TShark et les interfaces de capture. Chaque installation demande une réponse. Windows propose Python 3.13 et Wireshark avec winget ; terminer l'installateur interactif en incluant TShark et Npcap. Sans winget, installer Python depuis son site officiel puis relancer. Debian/Ubuntu utilisent apt lorsque disponible ; les autres systèmes reçoivent des instructions manuelles. Des droits administrateur peuvent être nécessaires.

Les modules Python requis sont `cryptography` et `dnspython`. Leur absence ou une version incompatible bloque l'exécution. Refuser TShark permet les sondes sans capture ; une capture explicitement demandée échoue si ses prérequis manquent. Une dépendance absente n'est jamais interprétée comme du filtrage. L'interface graphique Wireshark est utile, mais c'est TShark qui sert à l'automatisation.

| Fonction | Prérequis |
|---|---|
| Menus, sondes et rapports | Python 3.11+, venv/pip et requirements.txt |
| Lecture de PCAP | TShark |
| Capture en direct | TShark, Npcap sous Windows ou libpcap sous Unix, autorisations |
| ECH actif | curl compilé avec `--ech hard`, pas simplement un curl quelconque |
| Traceroute inverse | SSH et machine distante contrôlée disposant de traceroute/tracert |

Installation manuelle Windows :

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python main.py --doctor
.venv\Scripts\python main.py
```

Sous Linux : créer l'environnement avec `python3 -m venv .venv`, puis remplacer `.venv\Scripts\python` par `.venv/bin/python`. Installer le paquet venv/pip de la distribution si nécessaire. `--doctor` vérifie les outils locaux sans envoyer de sondes ; le code 2 signale un prérequis central ou de capture absent. Une interface visible ne garantit pas les droits de capture.

Windows est testé localement. La CI couvre Linux ; la validation terrain sur matériel Linux/OpenWrt reste à faire. Sur OpenWrt, privilégier une courte capture tcpdump sur le routeur puis son analyse sur ordinateur. L'installation complète sur routeur reste expérimentale selon architecture, mémoire et paquets disponibles. Le lanceur ne modifie ni routes ni pare-feu.

## Menu

Choisir français, anglais, russe ou chinois simplifié au premier démarrage ; l'option 6 permet de changer ensuite. Seul le code de langue est enregistré dans la configuration utilisateur. Menus et saisies sont traduits ; sorties techniques et rapports ne le sont pas intégralement. L'installation emploie actuellement anglais/français.

1. Diagnostic général : rapide, complet ou tests à la carte ; capture facultative en mode complet.
2. Diagnostic VLESS/REALITY à partir des fichiers et captures disponibles.
3. Outils avancés : double capture, ECH passif/actif, liste des interfaces.
4. Comparer deux rapports détaillés.
5. Préparer un export réduit pour partage volontaire.
6. Changer de langue ; 0 pour quitter.

La batterie complète couvre TCP/443, HTTP, SNI, TTL, RST, TLS malformé, différences entre destinations, HTTP Host, DNS, segmentation des écritures TCP, variantes TLS, empreintes de ClientHello artisanal, mutations TLS et publication ECH. Les noms historiques « bypass » et « fragmentation » ne promettent ni contournement applicatif validé ni fragmentation IP. Un passage complet peut prendre plusieurs minutes. `--samples` répète les sondes qui prennent en charge l'échantillonnage, pas chaque opération.

## Commandes

Utiliser le Python de l'environnement. Sans argument, le programme exige un terminal interactif ; `--auto` déclenche explicitement le mode rapide automatique.

```text
python main.py --help
python main.py --version
python main.py --auto
python main.py 1.1.1.1 --samples 3 --profile direct
python main.py 1.1.1.1 --samples 3 --profile autre-reseau --pcap --pcap-interface 3
python main.py --multi --samples 3
python main.py --compare reports/direct.json reports/autre.json
python main.py --ech example.com
python main.py --ech example.com --ech-active
python main.py --anonymize reports/direct.json
```

Remplacer 3 par une interface affichée dans les outils avancés. La capture du mode complet vise le port 443 de la cible ; elle n'inclut pas tous les échanges DNS ni toutes les autres destinations. `targets.json` configure les cibles IPv4 et groupes de domaines. Les cibles anycast publiques par défaut ne sont pas des serveurs contrôlés faisant autorité pour chaque SNI. Les groupes `blocked`/`clean` ne constituent pas des classifications démontrées. Pour attribuer un comportement, privilégier des serveurs contrôlés et des tests autorisés.

ECH actif utilise curl avec `--ech hard`, le DoH Cloudflare, la validation des certificats et sans proxy HTTP d'environnement. Succès, capacité absente, exigence ECH non satisfaite et erreur de transport restent distincts. Le routage TUN peut toujours s'appliquer. La publication DNS seule ne valide pas ECH ; un échec ECH seul ne prouve pas un filtrage.

### Tunnel et captures synchrones

```text
python main.py --diagnose-tunnel --sing-box-config config.json --outbound-tag reality --sing-box-log client.log --tunnel-endpoint SERVER_IP:443 --tunnel-pcap client.pcapng --server-pcap server.pcapng --diagnosis-output reports/incident.json
python main.py --dual-pcap client.pcapng server.pcapng --tunnel-endpoint SERVER_IP:443 --flow-output reports/paired.json
tshark -D
tshark -i 3 -f "host SERVER_IP and tcp port 443" -a duration:30 -w client.pcapng
tcpdump -i any -s 0 -w server.pcap 'tcp port 443'
```

Remplacer les paramètres d'exemple, retirer les fichiers facultatifs absents, choisir un tag de sortie unique. Pour une capture historique, fournir l'IP réellement utilisée au moment de l'incident. Capturer la même tentative aux deux extrémités avec des horloges synchronisées. Le menu demande de reproduire la connexion avec le client existant : dpi-probe ne réalise pas lui-même une authentification REALITY. Un TLS ordinaire réussi peut venir du fallback.

`--active-tunnel-checks` ajoute TCP/traceroute vers le serveur. Sous Windows, `--underlay-interface-index N` sélectionne l'interface physique pour la sonde TCP ; cet index Windows diffère du numéro TShark. Une photographie des routes ne garantit pas que chaque sonde évite le TUN. L'API locale peut être interrogée via `--sing-box-api http://127.0.0.1:9090` et `--sing-box-secret-env NOM_VARIABLE` ; URL distante et redirection sont refusées.

Le traceroute inverse exige un agent distant que vous contrôlez :

```text
python main.py --reverse-trace PUBLIC_IP --reverse-agent probe@CONTROLLED_HOST
```

## Rapports et confidentialité

Les rapports détaillés généraux et tunnel ont une version JSON et Markdown. Les sorties rapides, ECH et double capture ont des formats distincts, pas tous acceptés par le comparateur détaillé. Les résultats restent dans `reports/`, sauf chemin explicitement choisi. Aucun envoi automatique ni surveillance continue.

NAT, asymétrie, offload, captures incomplètes et pertes de capture peuvent modifier l'interprétation. L'appariement utilise signatures TCP et plages de séquences, sans authentifier le contenu des paquets. Des plages absentes ne mesurent pas un taux de perte réseau.

Captures, configurations et logs peuvent révéler adresses, domaines et secrets. Le masquage des secrets courants n'est pas universel. L'export tunnel réduit conserve des codes diagnostiques ; l'export général conserve encore les domaines testés. Relire avant partage. Git ignore rapports, logs, captures et environnements.

## Validation et version

```text
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m coverage run --source=src -m pytest -q
python -m coverage report --omit="src/probes/*" --fail-under=40
python -m compileall -q main.py bootstrap.py src
python main.py --help
git diff --check
```

Les tests couvrent schémas, régressions de diagnostic, menus, langues et PCAP synthétiques traités par le vrai TShark lorsqu'il est disponible. Une intégration facultative absente est explicitement ignorée. Cela ne valide pas la précision sur chaque FAI. La bêta attend des essais terrain contrôlés, davantage de validations d'installation et une relecture linguistique native.

Voir [audit technique](AUDIT_TECHNIQUE.md), [changements](CHANGELOG.md), [feuille de route](ROADMAP_RECHERCHE.md) et [licence MIT](LICENSE). Références : [Python](https://www.python.org/downloads/), [installation Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html), [ECH dans curl](https://curl.se/docs/manpage.html#--ech).
