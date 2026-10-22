# Contributing

Obrigado pelo interesse em contribuir com o Astral Platform & HCI!

## Idiomas disponíveis

| Idioma | Documento |
|--------|-----------|
| 🇧🇷 Português (Brasil) | [CONTRIBUTING.pt-BR.md](docs/i18n/CONTRIBUTING.pt-BR.md) |
| 🇺🇸 English | [CONTRIBUTING.en-US.md](docs/i18n/CONTRIBUTING.en-US.md) |
| 🇪🇸 Español | [CONTRIBUTING.es-ES.md](docs/i18n/CONTRIBUTING.es-ES.md) |
| 🇫🇷 Français | [CONTRIBUTING.fr-FR.md](docs/i18n/CONTRIBUTING.fr-FR.md) |

---

## Resumo

1. Faça um fork do repositório e crie sua branch a partir de `main`.
2. Siga o estilo de código existente (Spring Boot 3.3.5 / Java 21, Python, React).
3. **Não adicione `@Entity` sem uma migração.** O `ddl-auto` é `validate`;
   quem migra é o Flyway, em `src/main/resources/db/migration/`.
4. Adicione testes para novas funcionalidades.
5. Atualize a documentação correspondente.
6. Abra um Pull Request com título e descrição claros.

Veja o guia completo no seu idioma acima.