# 🔨 GoTemper

![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8?style=flat-square&logo=go)
![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)

**GoTemper** est un outil CLI en Go pour tester la **résilience et la sécurité** de services HTTP que vous êtes autorisé à tester : scripting de scénarios, détection de mauvaises configurations (headers manquants, CORS mal configuré, endpoints de debug exposés), avec rate limiting intégré et intégration CI/CD.

Dans la lignée de [k6](https://k6.io) (load testing) et [Nuclei](https://github.com/projectdiscovery/nuclei) (templates de détection) — mais pensé pour combiner les deux dans un seul outil pur Go.

> ⚠️ **Positionnement** : outil de test défensif et de validation, destiné aux équipes testant leurs propres systèmes ou avec autorisation explicite. Ce n'est pas un outil d'exploitation ciblée.

## Statut

🚧 En développement actif. La v0.1 couvre la vérification de headers de sécurité ; le scripting de scénarios, la génération de payloads de fuzzing et le reporting JSON/HTML arrivent ensuite.

## Installation

```bash
go install github.com/TALLHAMADOU/gotemper/cmd/gotemper@latest
```

## Utilisation

```bash
gotemper check --url https://api.example.com
gotemper check --url https://api.example.com --fail-on-critical

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

## Roadmap

- [x] Vérification des headers de sécurité
- [x] Fuzzing de payloads (CommonEdgeCases)
- [x] Détection CORS mal configuré
- [x] Détection d'endpoints de debug exposés
- [x] Rate limiting effectif sur les scénarios multi-requêtes
- [ ] Reporting JSON/HTML
- [ ] Intégration CI/CD (échec de pipeline sur régression de sécurité)

## Licence

MIT — voir [LICENSE](LICENSE).
