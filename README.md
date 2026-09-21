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
```

## Utilisation en tant que librairie

```go
scenario := gotemper.NewScenario("api-check").
    Target("https://api.example.com").
    CheckHeaders(gotemper.SecurityHeaders).
    RateLimit(100, time.Second)

report := gotemper.Run(scenario)
report.FailBuildIfCritical()
```

## Roadmap

- [x] Vérification des headers de sécurité
- [ ] Fuzzing de payloads (CommonEdgeCases)
- [ ] Détection CORS mal configuré
- [ ] Détection d'endpoints de debug exposés
- [ ] Rate limiting effectif sur les scénarios multi-requêtes
- [ ] Reporting JSON/HTML
- [ ] Intégration CI/CD (échec de pipeline sur régression de sécurité)

## Licence

MIT — voir [LICENSE](LICENSE).
