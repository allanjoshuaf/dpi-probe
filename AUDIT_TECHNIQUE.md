# Audit technique — mise à jour du 1er septembre 2026

## Conclusion

Le projet est maintenant cohérent comme **outil de collecte d'indices**. Il ne
doit plus être présenté comme un détecteur capable, à partir d'un simple
timeout, d'affirmer qu'un DPI existe ou de nommer son emplacement.

La localisation utile d'une panne VLESS/REALITY est faisable à trois niveaux :

1. le stade logiciel sing-box, avec le journal horodaté ;
2. le stade TCP du tunnel, avec une capture client ;
3. le sens de la divergence entre client et VPS, avec deux captures synchrones.

L'identification du routeur physique exact n'est pas obtenue avec ces seules
données. Elle exige un point de mesure intermédiaire ou une expérience TTL
contrôlée. Le reverse traceroute nécessite également un agent distant coopératif.

## Informations historiques corrigées

- Les IP `1.1.1.1`, `8.8.8.8` et `9.9.9.9` sont des services anycast publics,
  pas des serveurs contrôlés acceptant arbitrairement tous les SNI et Host.
- Un timeout signifie « aucune réponse avant le délai », pas « silent drop par
  un DPI ».
- Une lecture TCP vide est un EOF, pas un RST.
- Une différence entre résolveurs DNS ne prouve pas un empoisonnement : CDN,
  géolocalisation et split DNS sont aussi possibles.
- Un écart de délai après envoi de HTTP sur le port TLS ne localise pas un RST.
- Quelques TTL TCP échantillonnés ne prouvent ni suppression ICMP, ni hop DPI.
- Deux appels `sendall` ne garantissent pas deux paquets IP : le test mesure les
  frontières d'écriture TCP, pas la fragmentation IP.
- Une réponse obtenue après mutation/séparation TLS est un changement de
  résultat, pas un contournement confirmé.
- Le JA3 du ClientHello artisanal n'est pas l'identité d'un navigateur réel.
- ECH est défini par RFC 9849 et son amorçage DNS par RFC 9848. RFC 9505 est une
  étude des techniques de censure, pas la spécification ECH.

Les anciennes conclusions de terrain de la version 0.1 sont donc rétractées
dans `CHANGELOG.md`. Les mesures brutes restent exploitables avec prudence.

## Relecture fichier par fichier

| Fichier | État après audit |
|---|---|
| `main.py` | CLI validée, `--samples >= 1`, interface PCAP obligatoire, modes ECH, reverse trace, tunnel et double PCAP ajoutés ; erreur propre si la configuration est invalide. |
| `targets.json` | Cibles marquées non contrôlées et catégories de domaines traitées comme hypothèses. |
| `requirements.txt` | Dépendances d'exécution déclarées. |
| `requirements-dev.txt` | Pytest et validateur JSON Schema déclarés. |
| `pytest.ini` | Découverte limitée aux vrais fichiers `test_*.py`, évitant que les fonctions de sonde soient exécutées comme tests unitaires. |
| `schema.json` | Remplacé par un véritable JSON Schema 2020-12 pour les trois formats de sortie. |
| `src/__init__.py` et `src/probes/__init__.py` | Noms Python corrigés ; les anciens `_init_.py` erronés sont supprimés. |
| `src/config.py` | Validation IPv4/domaines et échec fermé : un JSON invalide ne déclenche plus des mesures sur des cibles par défaut sans prévenir. |
| `src/stats.py` | Nombre total d'échantillons conservé même lorsque tous les essais expirent. |
| `src/probe.py` | Chaque sonde peut échouer sans supprimer tout le rapport ; sémantique HTTP/PCAP rendue neutre. |
| `src/report.py` | Schéma 2.0 : observation, inférence, attribution et limites séparées ; plus de score arbitraire ni booléen DPI inventé. |
| `src/autodetect.py` | Résultat renommé comportement dépendant du contenu ; attribution non prétendue et confiance plafonnée. |
| `src/pcap.py` | Heuristiques fixes de TTL/fenêtre retirées ; compteurs bruts et direction du RST conservés. |
| `src/correlator.py` | Une IP source apparente n'est plus appelée automatiquement « serveur », car elle peut être usurpée. |
| `src/flow_analysis.py` | Chronologie par flux, distinction RST client/serveur apparent, fermeture FIN/FIN, et comparaison client/VPS par numéros TCP absolus. Les doublons de capture `any` ne créent plus une fausse divergence. |
| `src/tunnel_diagnose.py` | Inspection VLESS/REALITY sans UUID/clé, classification des logs, extraits expurgés, API Clash résumée, contrôles TCP/route et analyse PCAP. |
| `src/reverse_traceroute.py` | Reverse trace réel uniquement via un VPS SSH contrôlé ; paramètres et OS vérifiés. |
| `src/anonymize.py` | Compatible avec l'assessment v2 et l'ancien score. |
| `src/compare.py` | Compare l'assessment et la force des indices, avec compatibilité des anciens rapports. |
| `src/probes/sni_test.py` | Timeout, EOF, alerte et ServerHello séparés ; aucune attribution automatique. |
| `src/probes/http_host_test.py` | Différence Host classée sans confondre chemin et virtual host destination. |
| `src/probes/dns_test.py` | Divergence de vues DNS, pas diagnostic automatique d'empoisonnement. |
| `src/probes/ttl_test.py` | Échantillonnage de joignabilité, pas localisation de DPI. |
| `src/probes/rst_test.py` | RTT de connexion séparé du délai après envoi ; vrais événements socket conservés. |
| `src/probes/malformed_tls_test.py` | Profil de réponse uniquement ; le délai ne nomme pas le parseur. |
| `src/probes/ip_block_test.py` | Différence entre destinations, sans prétendre isoler l'IP ou le SNI. |
| `src/probes/fragmentation_test.py` | Renommé conceptuellement en segmentation d'écritures TCP. |
| `src/probes/bypass_test.py` | Champs et verdicts transformés en changements de résultat, sans « bypass confirmé ». |
| `src/probes/tls_fingerprint.py` | JA3/JA3S conservé comme empreinte du hello artisanal uniquement. |
| `src/probes/tls_mutation_test.py` | Mutation différentielle ; nouvelle clé X25519 à chaque ClientHello ; aucun clonage de navigateur revendiqué. |
| `src/probes/validate_bypass.py` | Nom historique conservé, mais résultat limité à la première réponse TLS et session applicative explicitement non validée. |
| `src/probes/ech_test.py` | Sépare publication DNS, API réellement disponible dans Python, et handshake tenté. |
| `tests/test_*.py` | 38 tests couvrent statistiques, configuration, comparaison, anonymisation, corrélation, rapport, schéma, ECH, reverse trace, phases PCAP, underlay et secrets sing-box. |
| `README.md` | Méthodologie, limites, commandes et références primaires corrigées. |
| `GUIDE_UTILISATEUR.md` | Documentation personnelle en français avec toutes les entrées à saisir. |
| `CHANGELOG.md` | Corrections recensées et anciennes conclusions non démontrées rétractées. |
| `LICENSE` | Licence MIT valide ; vérifier simplement que la mention d'auteur `Al` est celle souhaitée. |

## Ce que montre la dernière capture existante

La capture `reports/capture_1_1_1_1_20260627_051502.pcapng` est une capture de
sondes vers `1.1.1.1:443`, **pas une capture du serveur REALITY**. La nouvelle
analyse donne :

- 94 flux avec données bidirectionnelles ;
- 9 flux bidirectionnels avec retransmissions ;
- 68 RST envoyés par le client après des données restées sans réponse ;
- 13 RST envoyés par le client après une réponse ;
- 3 flux dont les premières données client restent sans réponse avec
  retransmissions ;
- 6 handshakes non complets dans la capture ;
- 6 connexions sans payload observé ;
- 1 RST apparent côté cible, mais seulement après une fermeture FIN/FIN déjà
  engagée : ce RST tardif n'explique pas le problème initial.

La précédente lecture « 82 RST du DPI » était donc fausse : 81 sont des resets
client, et le dernier est postérieur à une fermeture ordonnée. Les trois flux
sans réponse restent des observations intéressantes, mais une capture côté
`1.1.1.1` serait nécessaire pour dire si les données sont arrivées.

Le résultat détaillé régénéré se trouve dans
`reports/audit_existing_capture.json`.

### État de toute l'archive `reports/`

- 80 fichiers JSON contrôlés : 80 lisibles, aucun JSON corrompu ;
- 67 rapports déclarent le schéma historique `1.0` ;
- 13 des plus anciens n'ont pas de version de schéma ;
- 75 contiennent encore l'ancien score, qui ne doit pas être relu comme une
  preuve ;
- 56 captures PCAP/PCAPNG recensées ;
- 16 captures de 360 à 496 octets contiennent **zéro paquet**. Elles ne sont
  pas corrompues, mais seulement constituées de l'en-tête de capture et ne
  peuvent soutenir aucune analyse.

Ces archives n'ont pas été supprimées afin de préserver l'historique. Seuls les
nouveaux rapports produits par la version 0.2 suivent le schéma probant 2.0.

## Matrice de diagnostic VLESS/REALITY

| Dernier événement commun aux données | Zone probable à vérifier | Preuve suivante |
|---|---|---|
| SYN client sans SYN/ACK côté client ni SYN côté VPS | accès local, route, filtrage IP/port avant VPS | double PCAP + route directe/second accès |
| SYN visible client mais absent VPS | chemin aller entre les deux captures | double PCAP, puis point intermédiaire |
| TCP établi, ClientHello/charge client absente VPS | chemin aller après établissement | signatures TCP absolues des deux PCAP |
| Charge reçue VPS, aucune réponse émise | sing-box serveur, REALITY, clé, short ID, SNI de couverture, horloge | log serveur horodaté |
| Réponse émise VPS mais absente client | chemin retour | double PCAP |
| RST « serveur » seulement côté client | injection/usurpation compatible, mais perte/offload à exclure | captures complètes et horloges synchrones |
| Tunnel externe bidirectionnel, une destination interne seule échoue | DNS/routage/règle/outbound/egress serveur, pas nécessairement DPI du tunnel | log sing-box + API connexions + test serveur |
| Tunnel fonctionne puis cesse après délai fixe | idle timeout, NAT, keepalive, serveur, route ou politique temporelle | durée exacte, logs et PCAP couvrant avant/après |
| Petits échanges passent, gros flux cassent | MTU/PMTUD, perte, congestion ou segmentation | tailles progressives, ICMP PTB, MSS et double PCAP |

## État des données après la session Pakistan

La configuration client active, la version client, la topologie TUN/Ethernet,
la PCAP extérieure du véritable endpoint, la PCAP intérieure et plusieurs tests
de volume sont maintenant obtenus. L'adresse publique résidentielle n'est ni
collectée ni destinée à un reverse traceroute ; toute comparaison internationale
doit employer une seconde sonde de datacenter contrôlée.

Les données encore manquantes sont :

1. version sing-box du serveur ;
2. journaux client et serveur couvrant exactement la même panne ;
3. PCAP VPS synchrone avec la PCAP cliente ;
4. accès SSH administré ou mécanisme de capture fourni par l'opérateur ;
5. second accès réseau ou second VPS pour séparer un chemin particulier d'un
   comportement reproductible ;
6. endpoint contrôlé avec identifiant de sonde pour étalonner les tests SNI/Host.

Sans ces éléments, le logiciel peut dire **à quelle phase le client s'arrête**,
mais il ne peut honnêtement dire ni pourquoi sing-box a rejeté la session, ni à
quel endroit du chemin le paquet a disparu.

## Vérifications exécutées

- compilation de tous les fichiers Python ;
- suite complète sur Python 3.13 : 38 tests réussis ;
- CI GitHub configurée pour Python 3.11 et 3.13 ;
- couverture unitaire du cœur hors sondes réseau actives : 41 %, seuil CI
  initial fixé à 40 % et destiné à augmenter ;
- suite complète également vérifiée sur Python 3.11 avant l'ajout du test de
  schéma ;
- aide CLI chargée sans erreur ;
- schéma JSON validé par test ;
- `git diff --check` sans erreur de contenu ; seuls des avertissements de fins
  de ligne LF/CRLF Windows subsistent.

Les commandes opérationnelles complètes sont dans `GUIDE_UTILISATEUR.md`.
