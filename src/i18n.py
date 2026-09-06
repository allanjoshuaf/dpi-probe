"""Local CLI translations. Measurement keys and external tool output stay stable."""
import json
import os
from pathlib import Path

LANGUAGES = {'fr': 'Français', 'en': 'English', 'ru': 'Русский', 'zh': '简体中文'}
_language = 'fr'
_catalog = {key: dict(zip(('en', 'ru', 'zh'), values)) for key, values in
            json.loads((Path(__file__).parent / 'locales' / 'menus.json').read_text(encoding='utf-8')).items()}


def set_language(language):
    global _language
    if language not in LANGUAGES:
        raise ValueError('Unsupported language')
    _language = language


def tr(message):
    if _language == 'fr':
        return message
    return _catalog.get(message, {}).get(_language, message)


def settings_path():
    base = Path(os.environ.get('APPDATA') or os.environ.get('XDG_CONFIG_HOME') or (Path.home() / '.config'))
    return base / 'dpi-probe' / 'settings.json'


def load_language():
    try:
        value = json.loads(settings_path().read_text(encoding='utf-8'))
        language = value.get('language') if isinstance(value, dict) else None
        return language if language in LANGUAGES else None
    except (OSError, ValueError):
        return None


def save_language(language):
    if language not in LANGUAGES:
        raise ValueError('Unsupported language')
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'language': language}), encoding='utf-8')
    temporary.replace(path)
