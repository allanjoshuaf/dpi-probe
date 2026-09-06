# Guide utilisateur

Le guide complet est désormais disponible dans chaque langue, avec les mêmes
parcours d'installation, exemples et limites :

- [Français](README.fr.md)
- [English](README.md)
- [Русский](README.ru.md)
- [简体中文](README.zh.md)

Sous Windows, ouvrir `dpi-probe.cmd`. Sous Linux, lancer `sh dpi-probe.sh`.
Le lanceur propose les dépendances nécessaires avant d'ouvrir le menu.
Utiliser `python main.py --doctor` avec le Python de l'environnement pour
contrôler les prérequis locaux sans envoyer de sondes.

Pour un incident, conserver la même cible et les mêmes paramètres entre les
réseaux comparés. Reproduire brièvement, noter l'heure et capturer les deux
extrémités si possible. Garder les fichiers détaillés localement. Un timeout
isolé ne permet pas de conclure à un DPI ou de le localiser.
