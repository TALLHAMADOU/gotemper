# 🔨 GoTemper

![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8?style=flat-square&logo=go)
![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)

**GoTemper** est un outil CLI en Go pour tester la **résilience et la sécurité** de services HTTP que vous êtes autorisé à tester : scripting de scénarios, détection de mauvaises configurations (headers manquants, CORS mal configuré, endpoints de debug exposés), avec rate limiting intégré et intégration CI/CD.

Dans la lignée de [k6](https://k6.io) (load testing) et [Nuclei](https://github.com/projectdiscovery/nuclei) (templates de détection) — mais pensé pour combiner les deux dans un seul outil pur Go.

> ⚠️ **Positionnement** : outil de test défensif et de validation, destiné aux équipes testant leurs propres systèmes ou avec autorisation explicite. Ce n'est pas un outil d'exploitation ciblée.

## Statut

🚧 En développement actif. Toutes les briques du MVP sont posées : headers de sécurité, fuzzing, CORS, endpoints de debug, rate limiting effectif, reporting JSON/HTML et intégration CI/CD.

## Installation

```bash
go install github.com/TALLHAMADOU/gotemper/cmd/gotemper@latest
```

## Utilisation

```bash
gotemper check --url https://api.example.com
gotemper check --url https://api.example.com --fail-on critical

# Fuzzing des edge-cases courants (chaînes vides/géantes, quotes SQL,
# balises script, path traversal...) sur le paramètre "input"
gotemper check --url https://api.example.com --fuzz

# Sur un autre paramètre de requête
gotemper check --url https://api.example.com --fuzz --fuzz-param q

# Vérification CORS
gotemper check --url https://api.example.com --cors

# Recherche d'endpoints de debug/admin exposés
gotemper check --url https://api.example.com --debug-endpoints

# Rate limiting personnalisé (5 requêtes par 2 secondes)
gotemper check --url https://api.example.com --fuzz --rate-limit 5 --rate-window 2s

# Export du rapport
gotemper check --url https://api.example.com --fuzz --cors --output json > report.json
gotemper check --url https://api.example.com --fuzz --cors --output html > report.html
```

## Utilisation en tant que librairie

```go
scenario := gotemper.NewScenario("api-check").
    Target("https://api.example.com").
    CheckHeaders(gotemper.SecurityHeaders).
    CheckCORS().
    CheckDebugEndpoints().
    RateLimit(100, time.Second)

report := gotemper.Run(scenario)
report.FailBuildIfCritical()
```

Le fuzzing envoie chaque payload de `gotemper.CommonEdgeCases` (ou une liste personnalisée de `gotemper.Payload`) comme valeur d'un paramètre de requête, et détecte :
- les erreurs serveur (5xx) déclenchées par un payload,
- le reflet non échappé de balises/quotes dans la réponse (XSS potentiel),
- les fuites de traces d'erreur internes (stack traces, messages SQL bruts...).

`CheckCORS` envoie une requête avec un `Origin` arbitraire et détecte :
- `Access-Control-Allow-Origin: *` combiné à `Access-Control-Allow-Credentials: true` (critique),
- le reflet de n'importe quelle origine sans validation (élevé),
- un `Access-Control-Allow-Origin: *` seul, à confirmer si voulu (info).

`CheckDebugEndpoints` sonde une liste d'endpoints connus (`.env`, `.git/config`, `.aws/credentials`, Spring Actuator, pprof, phpinfo, Symfony profiler, Swagger, GraphQL, Prometheus `/metrics`...) sur la racine du domaine cible, et compare chaque réponse à une route aléatoire inexistante pour ne pas remonter de faux positifs sur les serveurs qui répondent 200 à tout (SPA catch-all).

`RateLimit(n, period)` s'applique à **toutes** les requêtes du scénario (header check, fuzzing, CORS, debug endpoints) via le `http.RoundTripper` du client — pas seulement au premier appel. Par défaut le CLI limite à 100 requêtes/seconde ; réglable avec `--rate-limit` et `--rate-window`.

`report.JSON()` / `report.WriteJSON(w)` exportent le scénario, un résumé par sévérité (`Summary`) et la liste des findings. `report.HTML()` / `report.WriteHTML(w)` génèrent une page autonome (thème sombre, un badge par sévérité) — via `html/template`, donc les payloads de fuzzing potentiellement réfléchis dans un message (`<script>...</script>`) sont toujours échappés, jamais rendus tels quels.

`--fail-on critical|high|info` (ou `report.FailBuildIfSeverity(seuil)` en librairie) fait échouer le processus avec un exit code non nul dès qu'un finding de cette sévérité ou pire est présent — c'est le point d'accroche pour faire échouer un pipeline CI sur une régression de sécurité. `report.FailBuildIfCritical()` reste disponible comme raccourci pour le seuil `critical`.

## Intégration CI/CD

GoTemper est pensé pour être lancé directement dans votre pipeline et faire échouer le build sur une régression. Exemple GitHub Actions :

```yaml
name: Security check

on:
  pull_request:
    branches: [main]

jobs:
  gotemper:
    runs-on: ubuntu-latest
    steps:
      - name: Install GoTemper
        run: go install github.com/TALLHAMADOU/gotemper/cmd/gotemper@latest

      - name: Run GoTemper against staging
        run: |
          gotemper check \
            --url https://staging.example.com \
            --fuzz --cors --debug-endpoints \
            --output json --fail-on critical > gotemper-report.json

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: gotemper-report
          path: gotemper-report.json
```

Le job échoue (exit code 1) dès qu'un finding `critical` est trouvé ; passez `--fail-on high` pour être plus strict. Le rapport JSON reste disponible comme artefact même quand le job échoue (`if: always()`), pour l'inspecter ou le publier ailleurs (dashboard, Slack...).

Le dépôt lui-même est testé sur chaque push/PR via [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (build, vet, tests avec `-race`).

## Roadmap

- [x] Vérification des headers de sécurité
- [x] Fuzzing de payloads (CommonEdgeCases)
- [x] Détection CORS mal configuré
- [x] Détection d'endpoints de debug exposés
- [x] Rate limiting effectif sur les scénarios multi-requêtes
- [x] Reporting JSON/HTML
- [x] Intégration CI/CD (échec de pipeline sur régression de sécurité)

## Licence

MIT — voir [LICENSE](LICENSE).
