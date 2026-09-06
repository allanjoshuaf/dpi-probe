import json
import unicodedata

import pytest

from src import cli_wizard, i18n


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(i18n, 'settings_path', lambda: tmp_path / 'settings.json')
    i18n.set_language('fr')
    yield
    i18n.set_language('fr')


@pytest.mark.parametrize('language,heading', [('fr', 'Menu principal'), ('en', 'Main menu'), ('ru', 'Главное меню'), ('zh', '主菜单')])
def test_each_language_renders_menu_and_exit(language, heading, monkeypatch, capsys):
    monkeypatch.setattr('builtins.input', lambda prompt='': '0')
    cli_wizard.run(language)
    output = capsys.readouterr().out
    assert heading in output
    assert i18n.tr('Quitter') in output
    for line in output.splitlines():
        if line.startswith('|'):
            width = sum(2 if unicodedata.east_asian_width(char) in {'W', 'F'} else 1 for char in line)
            assert width == 64


def test_first_launch_selects_and_remembers_language(monkeypatch, capsys):
    inputs = iter(['bad', '3', '0'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    cli_wizard.run()
    assert i18n.load_language() == 'ru'
    assert json.loads(i18n.settings_path().read_text()) == {'language': 'ru'}
    assert 'Главное меню' in capsys.readouterr().out
    monkeypatch.setattr('builtins.input', lambda prompt='': '0')
    cli_wizard.run()
    assert 'Главное меню' in capsys.readouterr().out


def test_language_can_change_without_restart(monkeypatch, capsys):
    inputs = iter(['6', '4', '0'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    cli_wizard.run('en')
    output = capsys.readouterr().out
    assert 'Main menu' in output and '主菜单' in output
    assert i18n.load_language() == 'zh'


def test_invalid_preferences_fall_back_to_selection():
    for value in ('{broken', '[]', '{"language":"xx"}'):
        i18n.settings_path().write_text(value)
        assert i18n.load_language() is None


def test_catalog_has_all_three_translations_and_matching_placeholders():
    from string import Formatter
    fields = lambda text: {name for _, name, _, _ in Formatter().parse(text) if name}
    for original, translations in i18n._catalog.items():
        assert set(translations) == {'en', 'ru', 'zh'}
        for text in translations.values():
            assert text.strip()
            assert fields(text) == fields(original)


def test_unwritable_preferences_keep_current_session(monkeypatch, capsys):
    def fail(language):
        raise OSError('read-only')
    inputs = iter(['2', '0'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    monkeypatch.setattr(i18n, 'save_language', fail)
    cli_wizard.run()
    output = capsys.readouterr().out
    assert 'could not be saved' in output
    assert 'Main menu' in output
