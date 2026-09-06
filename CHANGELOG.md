# Changelog

## 1.0.0-beta.1

### Utilisation

- Assistant terminal général avec tests rapides, complets ou à la carte,
  captures, ECH, comparaison, export et diagnostic VLESS/REALITY spécialisé.
- Menus français, anglais, russe et chinois simplifié avec préférence locale.
- README complets dans les quatre langues ; documentation publique séparée
  des observations de sessions privées.
- Lanceurs Windows/Linux : proposition d'installation de Python et des
  dépendances, environnement isolé, contrôle TShark et interfaces.
- `--doctor` vérifie les prérequis sans envoyer de sondes. Une capture
  explicitement demandée ne poursuit plus silencieusement sans TShark.
- Version centralisée ; rapports détaillés JSON et Markdown.

### Diagnostic

- Publication ECH séparée de la requête active `--ech-active`, qui exige ECH
  via curl et distingue les limitations de l'outil des erreurs réseau.
- Diagnostic tunnel avec sélection de sortie, étapes observées, causes
  possibles, données manquantes et double capture intégrée.
- Analyse TCP corrigée : sens des RST, chronologie FIN/RST, séquences avec
  wrap, plages segmentées/offload, captures vides et flux non appariés.
- Les ACK portés par un RST ne prouvent plus la réception du contenu.
- Absence de réponse conservée même sans retransmission ; les plages absentes
  ne sont pas présentées comme un taux de perte réseau.
- Références DNS inaccessibles classées comme inconclusives.
- Fermeture de sockets sur erreur, validation des paramètres, reprise des
  menus après erreur et sérialisation des traceroutes interrompus.

### Confidentialité et validation

- API sing-box limitée au loopback sans redirection ni proxy d'environnement.
- Secrets courants masqués dans les logs ; export tunnel réduit à des codes
  et métadonnées minimales. Le partage général conserve les domaines testés.
- Captures, logs, rapports et environnements exclus du dépôt.
- Tests de régression, menus et langues, PCAP synthétiques avec TShark réel
  lorsque disponible ; CI Python 3.11/3.13 sur Linux et Windows.

### Statut

Cette bêta remplace les descriptions expérimentales antérieures. Les anciennes
affirmations de « DPI confirmé », de localisation exacte ou de contournement
validé ne doivent pas être déduites des scores, timeouts ou premières réponses
TLS historiques. Pas de client REALITY authentifié intégré, pas de validation
terrain multi-FAI ou matérielle OpenWrt revendiquée. Voir l'audit technique.
