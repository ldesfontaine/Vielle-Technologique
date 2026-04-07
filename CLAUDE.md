# CLAUDE.md - veille-secu

## Projet & Stack
Moteur de veille cybersécurité. Collecte, filtre et notifie les CVEs et advisories pertinents pour un stack technique déclaré. Python + SQLite + Ntfy. Déployé comme container Docker par le repo deployZeroTrustV2.

## Règles Générales
- Toujours respecter les règles dans `.claude/rules/`
- À la fin de chaque session : si une nouvelle convention, pattern, décision d'archi ou style a été validée, crée ou mets à jour automatiquement le fichier le plus pertinent dans `.claude/rules/`. Garde chaque fichier < 80 lignes, ultra-concis.
- Ne jamais mettre de secrets ni de clés API dans le code. Tout passe par variables d'environnement (.env).
- Le document de référence est `docs/ARCHITECTURE.md`.

## Import automatique
L'agent charge automatiquement tout le dossier `.claude/rules/` et applique ce qui est pertinent pour la tâche en cours.
