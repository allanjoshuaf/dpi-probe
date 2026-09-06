"""Interactive terminal workflow; explicit choices before active measurements."""

from __future__ import annotations

import datetime
import platform
import ipaddress
import unicodedata
from pathlib import Path

from src import anonymize, compare, flow_analysis, pcap, tunnel_diagnose
from src import i18n
from src.i18n import tr


def choose(prompt: str, choices: dict[str, str], default: str | None = None) -> str:
    print(f"\n{tr(prompt)}")
    for key, label in choices.items():
        print(f"  {key}. {tr(label)}")
    while True:
        answer = input(f"{tr('Choix')}{' [' + default + ']' if default else ''} : ").strip() or default
        if answer in choices:
            return answer
        print(tr("Choisis un numéro de la liste."))


def file_input(prompt: str, default: str | None = None) -> str | None:
    while True:
        value = input(f"{tr(prompt)} [{default or tr('Entrée pour ignorer')}] : ").strip().strip('"')
        value = value or default
        if not value:
            return None
        path = Path(value).expanduser()
        if path.is_file():
            return str(path.resolve())
        print(tr("Fichier introuvable. Indique un fichier existant."))


def integer_input(prompt: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        value = input(f"{tr(prompt)} [{default}] : ").strip() or str(default)
        try:
            number = int(value)
            if minimum <= number <= maximum:
                return number
        except ValueError:
            pass
        print(tr("Entre un entier de {minimum} à {maximum}.").format(minimum=minimum, maximum=maximum))


def endpoint_input(default: str | None) -> str | None:
    while True:
        value = input(f"{tr('Serveur HOST:PORT')} [{default or tr('Entrée pour analyse des logs seuls')}] : ").strip() or default
        if not value:
            return None
        try:
            flow_analysis.parse_endpoint(value)
            return value
        except ValueError as exc:
            print(f"{tr('Adresse invalide')} : {exc}")


def diagnose() -> dict:
    print("\nDiagnostic VLESS / REALITY - Ctrl+C pour annuler.")
    print("Les rapports restent locaux. Les captures et journaux détaillés sont sensibles.")
    config_path = file_input("Configuration sing-box JSON")
    config = tunnel_diagnose.inspect_sing_box_config(config_path) if config_path else None
    rows = (config or {}).get('vless_outbounds', [])
    outbound_tag = None
    if len(rows) > 1:
        selected = choose("Quelle sortie VLESS diagnostiquer ?", {
            str(index + 1): f"{row.get('tag') or '(sans tag)'} - {row.get('server')}:{row.get('server_port')}"
            for index, row in enumerate(rows)
        })
        row = rows[int(selected) - 1]
        outbound_tag = row.get('tag')
        if not outbound_tag or sum(r.get('tag') == outbound_tag for r in rows) != 1:
            raise ValueError("Cette sortie doit avoir un tag unique dans la configuration sing-box.")
        config = {**config, 'vless_outbounds': [row]}
    endpoint = endpoint_input(tunnel_diagnose._select_endpoint(config, None))
    log_default = (config or {}).get('logging', {}).get('output')
    if isinstance(log_default, str):
        candidate = Path(log_default)
        if not candidate.is_absolute():
            candidate = Path(config_path).parent / candidate
        log_default = str(candidate) if candidate.is_file() else None
    else:
        log_default = None
    log_path = file_input("Journal sing-box de la reproduction", log_default)

    capture_mode = choose("Preuves réseau", {
        '1': 'Analyser une capture client existante',
        '2': 'Capturer maintenant pendant la reproduction du problème',
        '3': 'Continuer sans capture',
    }, '1')
    client_path = server_path = None
    session = Path('reports') / datetime.datetime.now(datetime.timezone.utc).strftime('incident_%Y%m%d_%H%M%S_%f')
    if capture_mode in {'1', '2'} and not endpoint:
        raise ValueError("Une capture nécessite l'adresse du serveur ; relance avec HOST:PORT.")
    if capture_mode == '1':
        client_path = file_input("Capture client PCAP/PCAPNG")
    elif capture_mode == '2':
        if not pcap.find_tshark():
            raise RuntimeError("TShark absent. Installe Wireshark/TShark (et Npcap sous Windows), ou analyse les logs sans capture.")
        host, port = flow_analysis.parse_endpoint(endpoint)
        addresses = flow_analysis.resolve_endpoint(host, port)
        selected = choose("IP à capturer (utilise celle du tunnel réel)", {str(i + 1): addr for i, addr in enumerate(addresses)}, '1')
        address = addresses[int(selected) - 1]
        endpoint = f'[{address}]:{port}' if ':' in address else f'{address}:{port}'
        interfaces = pcap.list_interfaces()
        if not interfaces:
            raise RuntimeError("Aucune interface de capture disponible. Vérifie les droits et Npcap/libpcap.")
        interface_rows = {line.split('.', 1)[0].strip(): line for line in interfaces if line.split('.', 1)[0].strip().isdigit()}
        if not interface_rows:
            raise RuntimeError("La liste des interfaces TShark n'a pas pu être interprétée.")
        interface = choose("Interface physique pour la capture (évite le TUN)", interface_rows)
        duration = integer_input("Durée de capture en secondes", 30, 5, 300)
        print("La capture commence. Reproduis maintenant le problème dans ton client VLESS/REALITY.")
        print("Le rapport analysera cette tentative ; dpi-probe ne s'authentifie pas lui-même à REALITY.")
        session.mkdir(parents=True, exist_ok=True)
        client_path = str(session / 'client.pcapng')
        result = pcap.capture(address, client_path, duration=duration, interface=interface, port=port)
        if result.get('status') != 'ok':
            raise RuntimeError(f"Capture échouée : {result.get('stderr') or result.get('detail') or result.get('error') or result.get('status')}")
    if client_path:
        server_path = file_input("Capture serveur de la même tentative (facultative)")

    active = False
    interface_index = None
    if endpoint:
        active = choose("Tests de joignabilité actuels (séparés de la capture)", {
            '1': 'Analyser seulement les preuves fournies',
            '2': 'Ajouter TCP, TLS de couverture si disponible, et traceroute',
        }, '1') == '2'
        if active:
            print("Ces tests ouvrent des connexions au serveur. TLS ordinaire ne valide pas REALITY.")
            if platform.system().lower() == 'windows':
                print("Si un TUN est actif, utilise l'ifIndex physique fourni par Get-NetIPInterface.")
                print("Cet index Windows est distinct du numéro TShark. 0 conserve la route système.")
                interface_index = integer_input("ifIndex Windows", 0, 0, 2**31 - 1) or None
            else:
                print("Les tests actifs utilisent la route système : vérifie qu'elle passe hors TUN.")
    if not any((config_path, log_path, client_path, active)):
        raise ValueError("Aucune preuve fournie. Ajoute au moins une configuration, un journal, une capture ou les tests actifs.")
    print("\nAnalyse en cours… Le traceroute peut prendre jusqu'à 45 secondes.")
    result = tunnel_diagnose.run(
        endpoint=endpoint, config_path=config_path, outbound_tag=outbound_tag,
        log_path=log_path, pcap_path=client_path, server_pcap_path=server_path,
        active_checks=active, samples=3, underlay_interface_index=interface_index,
        output_path=str(session / 'diagnosis.json'),
    )
    print(f"\nÀ lire : {(session / 'diagnosis.md').resolve()}")
    if choose("Créer également une copie minimale pour partage ?", {'1': 'Non', '2': 'Oui, codes de diagnostic uniquement'}, '1') == '2':
        shared = anonymize.anonymize_report(result)
        path = anonymize.save_anonymized(shared, str(session / 'diagnosis.shared.json'))
        print(f"Copie de partage : {Path(path).resolve()}")
    return result


def ipv4_input() -> str:
    while True:
        value = input(tr('IPv4 de la cible à tester') + ' : ').strip()
        try:
            if ipaddress.ip_address(value).version == 4:
                return value
        except ValueError:
            pass
        print(tr('Ces sondes demandent une adresse IPv4 valide.'))


def network_tests() -> None:
    from src import autodetect, config as cfg, report
    from src.probe import Probe

    action = choose('Tests réseau - ces mesures génèrent du trafic', {
        '1': 'Rapide : comparaison générale sur les cibles configurées',
        '2': 'Complet : toutes les sondes sur une IPv4 (plusieurs minutes)',
        '3': 'À la carte : choisir une sonde précise',
        '0': 'Retour',
    })
    if action == '0':
        return
    config = cfg.load()
    if action == '1':
        result = autodetect.run(config)
        directory = Path('reports') / datetime.datetime.now(datetime.timezone.utc).strftime('quick_%Y%m%d_%H%M%S_%f')
        flow_analysis.save_analysis(result, str(directory / 'quick.json'))
        print(f"Résultat enregistré : {(directory / 'quick.json').resolve()}")
        return
    target = ipv4_input()
    samples = integer_input('Répétitions pour les sondes compatibles', 3, 1, 20)
    probe = Probe(target, samples=samples, config=config, profile='guided')
    if action == '2':
        if choose('Ajouter une capture TShark pendant les sondes ?', {'1': 'Sans capture', '2': 'Avec capture sur une interface choisie'}, '1') == '2':
            interfaces = pcap.list_interfaces()
            options = {line.split('.', 1)[0].strip(): line for line in interfaces if line.split('.', 1)[0].strip().isdigit()}
            if not options:
                raise RuntimeError('TShark ou interfaces indisponibles ; installe les outils de capture ou choisis sans capture.')
            probe.pcap = True
            probe.pcap_interface = choose('Interface de capture', options)
            print('La capture des sondes cible TCP/443. Les requêtes DNS sont détaillées dans le rapport des résolveurs.')
        probe.run()
        return
    methods = {
        '1': ('TCP : joignabilité du port 443', probe.test_tcp_rst),
        '2': ('TLS : réponses selon le SNI', probe.test_sni),
        '3': ('DNS : comparaison des résolveurs', probe.test_dns),
        '4': ('HTTP : réponses selon le Host', probe.test_http_host),
        '5': ('RST : réponse à des données invalides sur 443', probe.test_rst),
        '6': ('TTL : joignabilité avec différents TTL', probe.test_ttl),
        '7': ('Avancé : segmentation des écritures TCP', probe.test_fragmentation),
        '8': ('Avancé : découpage des records TLS et padding', probe.test_bypass),
        '9': ('Avancé : mutations du ClientHello TLS', probe.test_tls_mutation),
        '10': ('Avancé : empreintes TLS JA3/JA3S', probe.test_tls_fingerprint),
        '11': ('Avancé : messages TLS malformés', probe.test_malformed_tls),
        '12': ('IP : comparaison des destinations configurées', probe.test_ip_blocking),
        '13': ('ECH : publication DNS et capacité locale (handshake non exécuté)', probe.test_ech),
        '0': ('Retour', None),
    }
    selected = choose('Choisis une sonde (un résultat ne prouve pas à lui seul un DPI)', {k: v[0] for k, v in methods.items()})
    if selected == '0':
        return
    methods[selected][1]()
    result = report.generate(target, probe.results, profile='guided', samples=samples)
    report.print_summary(result)
    print(f'Rapport enregistré : {Path(report.save(result)).resolve()}')


def advanced_tools() -> None:
    action = choose('Outils avancés', {
        '1': 'Comparer une capture client et une capture serveur',
        '2': 'ECH : publication DNS ou véritable requête avec ECH obligatoire',
        '3': 'Lister les interfaces de capture',
        '0': 'Retour',
    })
    if action == '1':
        client, server = file_input('Capture client'), file_input('Capture serveur')
        if not client or not server:
            return
        endpoint = endpoint_input(None)
        if not endpoint:
            raise ValueError('Une adresse serveur est nécessaire pour comparer les captures.')
        result = flow_analysis.compare_vantages(client, server, endpoint)
        output = Path('reports') / datetime.datetime.now(datetime.timezone.utc).strftime('dual_%Y%m%d_%H%M%S_%f.json')
        flow_analysis.save_analysis(result, str(output))
        print(f"Constat : {result['assessment']}\nRapport : {output.resolve()}")
    elif action == '2':
        from src.config import _validate_hostname
        from src.probes import ech_test
        hostname = input(tr('Nom de domaine') + ' : ').strip()
        _validate_hostname(hostname)
        active = choose('Mode ECH', {'1': 'Publication DNS et capacité Python seulement', '2': 'Ajouter une requête ECH obligatoire via curl + DoH Cloudflare'}, '1') == '2'
        result = ech_test.run(hostname, active=active)
        output = Path('reports') / datetime.datetime.now(datetime.timezone.utc).strftime('ech_%Y%m%d_%H%M%S_%f.json')
        flow_analysis.save_analysis(result, str(output))
        print(f'Rapport : {output.resolve()}')
    elif action == '3':
        interfaces = pcap.list_interfaces()
        print('\n'.join(interfaces) if interfaces else 'Aucune interface disponible : vérifier TShark et les droits de capture.')


def select_language() -> None:
    selection = choose('Langue / Language / Язык / 语言',
                       {str(i + 1): label for i, label in enumerate(i18n.LANGUAGES.values())})
    language = list(i18n.LANGUAGES)[int(selection) - 1]
    i18n.set_language(language)
    try:
        i18n.save_language(language)
    except OSError:
        print(tr("Langue appliquée pour cette session, mais impossible de l'enregistrer."))


def banner_line(message: str) -> str:
    text = tr(message)
    width = sum(2 if unicodedata.east_asian_width(char) in {'W', 'F'} else 0 if unicodedata.combining(char) else 1 for char in text)
    space = max(0, 62 - width)
    return '|' + ' ' * (space // 2) + text + ' ' * (space - space // 2) + '|'


def run(language: str | None = None) -> None:
    selected = language or i18n.load_language()
    if selected:
        i18n.set_language(selected)
    else:
        select_language()
    print(tr("Menus traduits ; sorties techniques des sondes et rapports dans leur langue d'origine."))
    while True:
        print('\n' + '+' + '-' * 62 + '+')
        print(banner_line('DPI-PROBE - ASSISTANT RÉSEAU'))
        print(banner_line('Observer · Comprendre · Localiser'))
        print('+' + '-' * 62 + '+')
        print(tr('Choisis un numéro. Ctrl+C interrompt l’opération en cours.'))
        action = choose('Menu principal', {
            '1': 'Diagnostic réseau : rapide, complet ou à la carte',
            '2': 'Diagnostic de tunnel VLESS / REALITY',
            '3': 'Outils avancés : captures, ECH, interfaces',
            '4': 'Comparer deux rapports',
            '5': 'Créer une copie de partage d’un rapport',
            '6': 'Langue / Language / Язык / 语言',
            '0': 'Quitter',
        }, '1')
        if action == '0':
            print(tr('À bientôt. Les rapports sont conservés dans reports/.'))
            return
        try:
            if action == '1':
                network_tests()
            elif action == '2':
                diagnose()
            elif action == '3':
                advanced_tools()
            elif action == '4':
                first, second = file_input('Premier rapport JSON'), file_input('Deuxième rapport JSON')
                if first and second:
                    compare.run(first, second)
            elif action == '5':
                source = file_input('Rapport JSON')
                if source:
                    anonymize.run(source)
            elif action == '6':
                select_language()
        except KeyboardInterrupt:
            print('\n' + tr('Opération interrompue. Retour au menu.'))
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"\n{tr('Impossible de terminer')} : {exc}")
            print(tr('Corrige les informations ou les outils indiqués, puis réessaie depuis le menu.'))
