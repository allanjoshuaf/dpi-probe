# Audit technique de 1.0.0-beta.1

## Périmètre

dpi-probe est une batterie générale de diagnostic réseau. Elle observe DNS,
TCP, TLS/SNI, HTTP Host, ECH, resets, segmentation et différences entre chemins.
VLESS/REALITY est un module spécialisé. Les anciens scores ou formulations
affirmatives ne constituent pas des preuves de DPI.

## Garanties de méthode

- Observation, hypothèse, attribution et preuve manquante restent distinctes.
- Un timeout ne prouve pas un filtrage ; un RST ne prouve pas une injection.
- Les endpoints anycast publics ne sont pas contrôlés ni autoritaires pour
  chaque SNI. Les groupes de domaines sont des hypothèses de comparaison.
- Une publication DNS ECH ne vaut pas handshake. Le mode actif exige
  `curl --ech hard` ; capacité absente et erreur transport sont distinctes.
- Un TLS de couverture réussi peut provenir du fallback REALITY.
- Deux captures bornent un écart entre observations, sans identifier un routeur.

## Corrections vérifiées par régression

L'analyse des flux tient compte du sens, des séquences absolues et de leur wrap,
des plages segmentées et de la chronologie FIN/RST. Les ACK dans les resets ne
valident pas la réception. Captures vides, flux non appariés et absence de
réponse sans retransmission sont traités explicitement. L'appariement repose
sur des signatures TCP, sans authentification du contenu ni mesure automatique
des pertes de capture.

La sélection sing-box utilise un tag unique. Les erreurs DNS sont conservées.
Les paramètres endpoint/port/short ID sont validés. Les sockets sont fermées
lors des erreurs et les traceroutes interrompus restent sérialisables. L'API
Clash est limitée au loopback, sans redirection ni proxy d'environnement.

Les dépendances Python sont contrôlées avant les sondes. Le lanceur propose
leur installation isolée et contrôle les outils de capture. Une capture
demandée ne démarre pas les sondes si TShark manque ou échoue au démarrage.
Lister une interface ne garantit pas les droits de capture. Une panne de
capture ultérieure reste une limitation des preuves recueillies.

## Validation

La suite pytest couvre les schémas, menus et quatre langues, rapports,
comparaison, export, erreurs de sondes, synthèse tunnel, installation et analyse
de flux. Les tests d'intégration génèrent des PCAP localement et utilisent le
TShark installé ; ils signalent explicitement son absence. Aucun trafic vers
un FAI n'est nécessaire à ces tests.

La CI est configurée pour Python 3.11/3.13 sous Ubuntu et Windows ; TShark est
installé dans le job Ubuntu. Les commandes de validation et le seuil de
couverture du cœur sont dans les README et AGENTS.md.

Bilan local du 6 septembre 2026 : **102 tests passent**, dont l'intégration
TShark réelle sur PCAP synthétiques. Couverture du cœur hors sondes actives :
**62 %** ; analyse de flux : **92 %**. Compilation et aide CLI passent.
Le lanceur a créé un nouvel environnement Python 3.13, installé les dépendances,
affiché le choix de langue puis ouvert et fermé le menu en terminal. La suite
passe également dans cet environnement neuf. Les scripts PowerShell et shell
passent leur contrôle syntaxique. TShark/Npcap étaient déjà présents : leur
installation sur une machine Windows vierge n'a pas été rejouée.

## Limites avant une version stable

- Pas de validation terrain multi-FAI, ni identification fiable d'un moteur
  DPI ou de son emplacement précis.
- Pas de validation matérielle Linux/OpenWrt ; les tests Windows et PCAP
  synthétiques ne la remplacent pas.
- Pas de client REALITY authentifié intégré ni de validation applicative
  systématique des variantes TLS.
- Pas de corrélation temporelle automatique de chaque ligne de log à un flux,
  ni correction automatique de NAT, pertes de capture ou décalage d'horloge.
- Réussite ECH active dépendante d'un curl compatible et de l'endpoint ; une
  simulation de retour curl n'est pas une validation ECH terrain.
- Installation interactive des pilotes et paquets dépendante des droits et
  du système ; la validation sur machines vierges reste à élargir.
- Traduction partielle des sorties techniques ; relecture native russe et
  chinoise encore nécessaire.
- Pas de campagnes distribuées, tableau de dérive ou corrélation OONI
  automatique. ROADMAP_RECHERCHE.md décrit des travaux futurs.

## Publication

La documentation ne contient plus de compte rendu d'incident personnel.
Les rapports, logs, captures et environnements restent locaux et ignorés par
Git. Le masquage des secrets courants n'est pas universel : inspecter tout
export avant partage, notamment les domaines conservés dans l'export général.
La licence existante est conservée.

Références : [REALITY](https://github.com/XTLS/REALITY/blob/main/README.en.md),
[TLS sing-box](https://sing-box.sagernet.org/configuration/shared/tls/),
[ECH curl](https://curl.se/docs/manpage.html#--ech).
