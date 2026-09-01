# Guide personnel — dpi-probe

Toutes les commandes ci-dessous sont à saisir dans PowerShell depuis
`C:\dpiProbe\dpi-probe`.

## 1. Préparer le projet

```powershell
py -m pip install -r requirements.txt
py -m pip install -r requirements-dev.txt
py -m pytest -q
py -m coverage run --source=src -m pytest -q
py -m coverage report --omit="src/probes/*"
py main.py --help
```

Le test doit finir sans erreur. Pour les PCAP, installe Wireshark avec TShark et
Npcap, puis trouve le numéro de ta vraie interface réseau :

```powershell
py -c "from src import pcap; [print(i) for i in pcap.list_interfaces()]"
```

## 2. Mesures générales

| Besoin | Commande exacte |
|---|---|
| Observation rapide | `py main.py` |
| Tous les tests sur une IP | `py main.py 1.1.1.1 --samples 3 --profile direct` |
| Toutes les IP de `targets.json` | `py main.py --multi --samples 3 --profile direct` |
| Même test dans le tunnel | `py main.py 1.1.1.1 --samples 3 --profile reality` |
| Capture incluse | `py main.py 1.1.1.1 --samples 3 --pcap --pcap-interface 3` |
| Comparer direct/tunnel | `py main.py --compare reports\direct.json reports\reality.json` |
| Anonymiser | `py main.py --anonymize reports\report.json --isp ExampleISP --country XX` |
| Version | `py main.py --version` |

Entrées :

- `1.1.1.1` : IPv4 de mesure, pas forcément le vrai serveur des domaines ;
- `--samples N` : entier supérieur ou égal à 1, viser 3 à 5 ;
- `--profile TEXTE` : étiquette libre (`direct`, `reality`, `mobile`, etc.) ;
- `--pcap-interface N` : numéro TShark vérifié, jamais deviné ;
- `--compare A B` : deux rapports JSON existants ;
- `--isp` et `--country` : informations facultatives ajoutées au rapport anonymisé.

## 3. Lire correctement un rapport

Le rapport v2 ne donne plus arbitrairement `DPI detected: yes/no`. Il contient :

- `observation` : mesure brute ;
- `inference` : explication compatible avec la mesure ;
- `attribution` : ce que l’on peut rattacher au client, au chemin ou au serveur ;
- `limitations` : ce qui empêche une conclusion plus forte.

`no_response_before_timeout` signifie seulement qu’aucune réponse n’est arrivée
avant le délai. `connection_closed_no_data` est une fermeture sans données, pas
un RST. Un vrai RST doit être observé par la socket ou dans le PCAP.

Les listes `clean` et `blocked` de `targets.json` sont des hypothèses de
comparaison. Les IP publiques sont anycast et non contrôlées. Elles ne peuvent
pas, seules, prouver qui traite le SNI ou le Host.

## 4. Diagnostiquer sing-box / VLESS REALITY

### Configuration seule

```powershell
py main.py --diagnose-tunnel --sing-box-config C:\chemin\config.json
```

Le rapport ne copie ni UUID ni clé publique. Il vérifie notamment : serveur,
port, présence UUID, `xtls-rprx-vision`, TLS, `server_name`, REALITY,
`public_key`, taille/format du `short_id`, vérification du certificat et uTLS.

### Configuration + journal + capture client

```powershell
py main.py --diagnose-tunnel `
  --sing-box-config C:\chemin\config.json `
  --sing-box-log C:\chemin\box.log `
  --tunnel-pcap C:\chemin\client.pcapng `
  --tunnel-endpoint ADRESSE_DU_VPS:443 `
  --diagnosis-output reports\reality_failure.json
```

Entrées :

- `--tunnel-endpoint HOST:PORT` : serveur réellement contacté par sing-box ;
- `--sing-box-config FILE` : JSON client sing-box ;
- `--sing-box-log FILE` : journal horodaté couvrant exactement la panne ;
- `--tunnel-pcap FILE` : capture client filtrée sur le VPS ;
- `--diagnosis-output FILE` : chemin facultatif du résultat.

Pour produire un journal exploitable durant une courte reproduction :

```json
{
  "log": {
    "disabled": false,
    "level": "debug",
    "output": "box.log",
    "timestamp": true
  }
}
```

Repasse ensuite au niveau `info`. Le debug peut contenir des destinations.

### Vérifications actives de l’endpoint

```powershell
py main.py --diagnose-tunnel `
  --sing-box-config C:\chemin\config.json `
  --tunnel-endpoint ADRESSE_DU_VPS:443 `
  --active-tunnel-checks `
  --underlay-interface-index 18
```

Cela fait trois connexions TCP, vérifie le certificat TLS du SNI de couverture
et lance un `tracert`. Remplace `18` par l'index de l'interface Ethernet/Wi-Fi
physique affiché par `Get-NetAdapter`. Sans cette contrainte, le test peut
repasser dans `tun0` et produire un faux trajet d'un hop. Une connexion TCP
réussie ne valide pas VLESS ; le contrôle TLS vérifie seulement que la façade
publique présente un certificat valide pour le `server_name`. Ce diagnostic ne
collecte pas l'adresse IP publique résidentielle.

### API Clash locale de sing-box

Si `experimental.clash_api.external_controller` est activé sur
`127.0.0.1:9090` :

```powershell
$env:DPI_PROBE_CLASH_SECRET = "secret-de-api"
py main.py --diagnose-tunnel `
  --sing-box-api http://127.0.0.1:9090 `
  --sing-box-secret-env DPI_PROBE_CLASH_SECRET
```

Ne mets pas le secret directement sur la ligne de commande. L’API ne doit pas
écouter sur `0.0.0.0` sans secret.

## 5. Savoir dans quel sens le paquet disparaît

Une capture client montre le moment de la panne mais pas ce que le VPS a reçu.
Il faut capturer des deux côtés pendant la même reproduction.

Côté client Windows :

```powershell
tshark -i 3 -f "host ADRESSE_DU_VPS and tcp port 443" -w client.pcapng
```

Côté VPS Linux :

```bash
sudo tcpdump -i any -nn 'tcp port 443' -w server.pcap
```

Analyse :

```powershell
py main.py --dual-pcap client.pcapng server.pcap `
  --tunnel-endpoint ADRESSE_DU_VPS:443 `
  --flow-output reports\dual_vantage.json
```

Résultats importants :

- `forward_path_packet_divergence` : données vues au départ du client mais pas
  dans la capture VPS ;
- `reverse_path_packet_divergence` : données vues au VPS mais pas à l’arrivée ;
- `reset_visible_at_client_but_absent_at_server_vantage` : RST apparent venant
  du serveur mais absent côté serveur, compatible avec une injection ; vérifier
  d’abord perte de capture et offload ;
- `reset_visible_at_server_vantage` : le RST existe déjà côté VPS ;
- `late_target_direction_reset_after_orderly_close` : RST tardif après une
  fermeture FIN/FIN déjà engagée, à ne pas confondre avec la cause initiale ;
- `no_material_divergence_in_matched_packets` : aucune différence matérielle
  trouvée avec les signatures TCP comparées.

L’analyse dit **entre quels points** et dans quel sens apparaît la différence.
Elle ne donne pas le routeur exact. Pour un hop exact, il faut une troisième
sonde intermédiaire ou une expérience TTL contrôlée avec paquets bruts.

## 6. Reverse traceroute

### Comprendre la destination

N'utilise jamais l'adresse IP résidentielle comme cible. Pour étudier un trajet
international retour, loue ou déploie une seconde sonde dans un datacenter sans
lien public avec le domicile. Le test se fait alors entre deux machines d'étude.
Quand le tunnel est actif, l'IP visible publiquement est généralement celle de
la sortie pakistanaise ; tracer du VPS pakistanais vers cette même IP ne serait
qu'un self-test sans valeur. Ce montage ne mesure pas le dernier kilomètre de la
connexion résidentielle, volontairement exclu pour protéger la vie privée.

### Préparer SSH

Le programme n'essaie pas de contourner l'administration du fournisseur. Il
faut un VPS que tu contrôles, une clé SSH et `traceroute` installé. Pour un port
SSH non standard, crée un alias dans `%USERPROFILE%\.ssh\config` :

```sshconfig
Host probe-pakistan
    HostName ADRESSE_DU_VPS
    User UTILISATEUR
    Port PORT_SSH
    IdentityFile C:\Users\TON_COMPTE\.ssh\id_ed25519
```

Vérifie d'abord l'accès non interactif :

```powershell
ssh -o BatchMode=yes probe-pakistan "date -u; traceroute --version"
```

Le serveur doit avoir une horloge synchronisée (`timedatectl status`) afin de
comparer proprement ses journaux avec ceux de Windows.

### Mesurer entre deux VPS contrôlés

```powershell
py main.py --reverse-trace IP_DU_SECOND_VPS `
  --reverse-agent probe-pakistan `
  --reverse-agent-os linux `
  --reverse-max-hops 30 `
  --reverse-timeout-ms 2000
```

Le VPS doit t’appartenir, accepter une clé SSH non interactive et disposer de
`traceroute`. Pour un agent Windows, utilise `--reverse-agent-os windows`.
Le retour peut suivre un chemin différent de l’aller.

### Capturer la même panne côté VPS

Dans une seconde console SSH, avant de reproduire la panne :

```bash
sudo timeout 90 tcpdump -i any -nn -s 0 'tcp port 443' -w /tmp/server-window.pcap
```

Récupère ensuite la capture :

```powershell
scp probe-pakistan:/tmp/server-window.pcap reports\server-window.pcap
```

Ne publie jamais cette PCAP brute. Après récupération et vérification, supprime
la copie temporaire du VPS :

```powershell
ssh probe-pakistan "rm -f /tmp/server-window.pcap"
```

Enfin, compare-la à la capture Ethernet cliente de la même fenêtre avec la
commande `--dual-pcap` de la section 5.

## 7. ECH

```powershell
py main.py --ech cloudflare-ech.com
```

Entrée : un nom DNS, jamais une URL. Le test distingue :

- configuration ECH publiée dans le record HTTPS/SVCB ;
- capacité du runtime TLS local ;
- handshake réellement tenté ou non.

Une configuration publiée n’est pas un handshake réussi. ECH est défini par
RFC 9849 et son amorçage DNS par RFC 9848.

## 8. Données à conserver pour une panne soudaine

Pour comprendre un tunnel qui fonctionne puis casse, garde le même fuseau et
une horloge correcte sur client/VPS, puis collecte :

1. heure précise du début et de la fin de la panne ;
2. journal sing-box horodaté niveau debug sur cette fenêtre ;
3. PCAP client de l’endpoint REALITY ;
4. PCAP VPS de la même fenêtre ;
5. configuration client analysée, sans la partager brute ;
6. profil réseau (`direct`, `reality`, opérateur, Wi-Fi/4G) ;
7. changement éventuel d’IP, route, MTU, SNI de couverture, version sing-box ;
8. si possible, un test identique depuis un second accès réseau.

Sans PCAP VPS, on peut savoir à quelle phase le client s’arrête. Avec les deux
PCAPs, on peut généralement déterminer le sens de la disparition ou la visibilité
du reset. Avec plusieurs points intermédiaires, on peut ensuite réduire la zone
du chemin responsable.
