# dpi-probe : passer des sondes à une plateforme expérimentale

État et proposition au 6 septembre 2026. Ce document décrit des travaux futurs,
pas des capacités déjà livrées. Il ne confirme aucun blocage précis sur
Rostelecom, Tele2 ou un autre opérateur sans les preuves de terrain associées.

## Positionnement mesurable

OONI dispose de mesures provenant de plus de 200 pays et d'un historique depuis
2012 ([Explorer](https://explorer.ooni.org/)). Son test Web Connectivity compare
les observations locales avec un test helper et spécifie les mesures DNS, TCP,
TLS et HTTP ainsi que leur interprétation
([spécification](https://github.com/ooni/spec/blob/master/nettests/ts-017-web-connectivity.md)).
Ses tests incluent aussi des outils de contournement
([catalogue](https://ooni.org/nettest/)). Il serait donc inexact de le réduire
à une sonde passive ou de prétendre le dépasser par le nombre de boutons.

L'hypothèse de positionnement pour dpi-probe : offrir une investigation
expérimentale fine d'un incident, avec contrôle des deux extrémités, variation
isolée des paramètres et critères de réussite applicatifs. Une supériorité sur
ce périmètre devra être démontrée par un benchmark commun, pas présumée.

## P0 - Établir une référence fiable

Construire un agent serveur coopératif et un laboratoire Linux isolé avec
namespaces, veth, nftables et netem. Reproduire des pertes aléatoires, refus TCP,
RST, blocages DNS, réponses DNS divergentes légitimes, MTU réduite, délais et
fermetures du serveur. Identifier chaque essai et relier ses logs aux captures
des deux extrémités. Documenter les pertes de capture, l'offload et les décalages
d'horloge. Une capture absente doit rendre l'attribution incertaine.

Critère de sortie : un corpus étiqueté indépendamment du classifieur, des
scénarios tenus à l'écart du développement, et des mesures de faux positifs,
faux négatifs et abstention par type d'incident. Fixer les objectifs numériques
avant le benchmark. Des simulations de filtrage ne prouvent pas une signature
commerciale TSPU réelle.

## P1 - Expériences comparatives reproductibles

Définir une expérience versionnée : cible, IP réellement utilisée, transport,
résolveur, interfaces, version du client, versions des outils, paramètres,
identifiant et heure UTC. Alterner aléatoirement contrôle et variante, modifier
un facteur à la fois et borner la durée, le débit et la concurrence. Rapporter
nombre d'essais, succès, erreurs par étape et intervalles d'incertitude.

Le schéma actuel des rapports est une base ; il manque un contrat commun de
campagne et une corrélation temporelle automatique. Les labels clean/blocked
des domaines actuels restent des hypothèses. Ni l'IP publique de mesure ni le
nom d'un FAI ne constituent une référence de vérité.

Critère de sortie : un tiers reproduit une campagne à partir du manifeste et
obtient des conclusions compatibles, avec les divergences explicables.

## P2 - Valider les techniques sur une session applicative

Comparer connexion témoin et variantes ECH, TLS record splitting, padding,
segmentation, REALITY et autres transports uniquement avec des clients et
serveurs compatibles. Un succès doit inclure authentification éventuelle,
requête complète et réponse attendue d'un service contrôlé, puis plusieurs
transferts et reconnexions. Mesurer stabilité, latence, débit et coût en octets.
Un ServerHello ou une alerte TLS ne suffit pas. Le domain fronting nécessite
une infrastructure qui le permet ; il ne s'agit pas d'une option universelle.

L'intégration curl ECH obligatoire existe, mais elle n'a pas encore été validée
sur le terrain avec un build compatible et un succès attesté. Les essais
REALITY authentifiés, les sessions complètes après mutation et les taux de
succès comparatifs ne sont pas implémentés. Ils demandent plus qu'un simple
enchaînement des sondes existantes.

Critère de sortie : une matrice contrôlée technique × réseau × version,
avec succès applicatif défini, témoins contemporains et répétitions.

## P3 - Renforcer la couverture des causes et protocoles

Étendre les sondes générales à IPv6 et QUIC/HTTP3 ; distinguer UDP filtré,
problème de MTU et négociation TLS. Pour DNS, comparer A/AAAA/HTTPS, UDP/TCP et
résolveurs chiffrés, suivre CNAME, cache et TTL, et effectuer une validation
DNSSEC locale lorsque la zone est signée. Le bit AD fourni par un résolveur
ne remplace pas à lui seul une validation de confiance. Tenir compte des CDN,
du split DNS et des politiques locales dans l'analyse des divergences.

Instrumenter routage, conntrack et compteurs nftables sur les hôtes contrôlés.
Employer eBPF seulement pour répondre à une question locale précise qui reste
ouverte après les captures. Ces outils ne révèlent pas magiquement le moteur
DPI situé chez un opérateur distant.

Critère de sortie : les pannes ordinaires sont distinguées des anomalies
compatibles avec filtrage dans les scénarios contrôlés correspondants.

## P4 - Campagnes longitudinales et terrain

Ajouter un mode campagne explicite avec stockage local indexé, reprise après
interruption, rotation, limites de trafic, historique des versions et détection
de changements. Ne pas lancer de surveillance de fond au simple démarrage.
Les comparaisons doivent tenir compte d'un changement d'IP, de route, de client
ou de résolveur avant d'attribuer un changement de résultat au filtrage.

Déployer ensuite avec des participants informés sur différents ASN, régions,
accès mobiles/fixes et créneaux horaires, en gardant des témoins communs. Une
marque commerciale peut couvrir plusieurs réseaux ; consigner le contexte
réel et expliquer les données manquantes et biais d'échantillonnage.

Critère de sortie : détection répétée d'un changement à paramètres comparables,
confirmée par un second point d'observation. Le volume seul n'est pas un
indicateur de représentativité.

## P5 - Interopérabilité et examen indépendant

Rapprocher les mesures OONI par domaine, ASN, période et méthode via son
[API publique](https://api.ooni.io/), avec provenance et liens conservés. Un
accord externe renforce le contexte sans prouver que la cause est identique.
Ajouter exports versionnés, corpus synthétiques publics, installation vérifiée
sur Windows/Linux/OpenWrt et releases reproductibles. Faire relire méthode et
résultats par des chercheurs externes.

Une comparaison loyale avec OONI doit fixer le périmètre, les versions,
conditions, critères et corpus ; accepter aussi les cas où OONI est meilleur.
Publier les limites, les taux d'erreur et les données partageables nécessaires
à la reproduction. Garder l'export volontaire et minimisé : pas de captures ou
de journaux privés envoyés automatiquement.

## Ordre proposé

Laboratoire + agent coopératif → contrat d'expérience + contrôles statistiques
→ validation applicative des variantes → couverture protocoles → campagnes
multi-réseaux → benchmark indépendant et publication.

Les langues et l'ergonomie facilitent l'adoption. Le gain scientifique décisif
vient de la capacité à expliquer un résultat et à mesurer quand l'outil se trompe.
