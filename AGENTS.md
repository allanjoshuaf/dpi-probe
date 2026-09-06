# dpi-probe - instructions persistantes

## Mission

Travailler comme un ingénieur réseau bas niveau. dpi-probe est une batterie
générale et détaillée de diagnostic réseau : comportements compatibles avec un
DPI, anomalies DNS et hypothèses de poisoning, TLS/SNI, HTTP Host, ECH, TCP/RST,
TTL, pertes, segmentation, empreintes et comparaison de chemins. Le diagnostic
VLESS/REALITY est un module spécialisé parmi ces fonctions, pas la définition
du produit. Expliquer les échecs et borner leur zone avec des preuves
reproductibles. Distinguer observation, hypothèse,
attribution et données manquantes. Un timeout, RST, TTL ou certificat TLS de
couverture ne prouve ni un DPI, ni son emplacement, ni une authentification
REALITY réussie.

## Outils et environnements

- Privilégier tcpdump pour la capture Linux/OpenWrt et Wireshark/tshark pour
  l'analyse, les filtres, les flux TCP et l'extraction automatisée.
- Sous Linux/OpenWrt, privilégier iproute2 (ip/ss), nftables et conntrack pour
  expliquer interfaces, routage, policy routing, pare-feu, NAT et état des flux.
  Commencer par l'observation et les compteurs existants.
- Employer eBPF/XDP seulement si les captures et compteurs ne répondent pas à la
  question, après vérification des capacités du noyau, des privilèges et du coût.
  Vérifier les particularités OpenWrt : BusyBox, paquets disponibles, mémoire et
  accélération matérielle/logicielle des flux.
- Conserver la prise en charge Windows : PowerShell, TShark/Npcap, Winsock et
  sélection de l'interface physique lorsque le TUN possède la route par défaut.
  Ne pas assimiler l'index d'interface Windows au numéro TShark.
- Utiliser Python pour les sondes, parsers, orchestration et tests du projet
  actuel. Envisager Go/Rust pour un besoin mesuré de performance, de distribution
  autonome ou d'intégration système ; éviter une réécriture sans justification.

## Méthode de diagnostic

- Vérifier successivement configuration, DNS, route hors TUN, TCP, TLS/REALITY,
  puis transfert et destination interne. Garder séparés réseau, client et serveur.
- Préférer une courte reproduction horodatée, une IP serveur explicite et des
  captures client/serveur de la même tentative. Consigner version du client,
  interface, sens, horodatage et paramètres de mesure.
- Tenir compte de NAT, IPv4/IPv6, asymétrie, pertes de capture, offload/GRO/TSO,
  segmentation, wrap des séquences et début/fin incomplets des captures.
- Comparer le même serveur et les mêmes paramètres sur un autre réseau avant
  d'attribuer un comportement à un FAI. Ne jamais annoncer un routeur exact sans
  preuve provenant de points d'observation supplémentaires.
- Adapter les outils disponibles à l'hôte réel. Des tests Windows ou PCAP
  synthétiques ne constituent pas une validation terrain Linux/OpenWrt.
- Avancer de manière autonome sur le code, les analyses et tests autorisés.
  Ne pas modifier les routes ou pare-feu d'une machine réelle dans le cadre
  d'une simple demande d'analyse ; préférer un laboratoire isolé pour les essais
  de pertes, resets et filtrage.
- Ne pas publier de captures, journaux ou credentials. Les exports de partage
  doivent être minimisés ; conserver les preuves détaillées localement.

## Validation et livraison

Automatiser les régressions significatives avec pytest et des fixtures locales.
Privilégier des PCAP synthétiques pour tester l'extracteur TShark réel sans
trafic externe. Les tests d'intégration dépendant d'un outil facultatif doivent
indiquer explicitement leur absence. Séparer ces tests des essais terrain.

Commandes (remplacer `py` par `python3` sous Linux) :

```text
py -m coverage run --source=src -m pytest -q
py -m coverage report --omit="src/probes/*" --fail-under=40
py -m compileall -q main.py src
py main.py --help
git diff --check
```

Documenter les nouvelles options dans README.md et GUIDE_UTILISATEUR.md, les
corrections dans CHANGELOG.md, et les limites vérifiées dans AUDIT_TECHNIQUE.md.
Expliquer au propriétaire en français ce qui fonctionne, ce qui a été testé et
ce qui reste une hypothèse. Les consignes explicites de la session priment sur
les préférences de ce fichier.
