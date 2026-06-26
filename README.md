# SSL-Watchdog

Monitor della salute dei domini - Controlla certificati SSL e dati WHOIS in tempo reale.

## 🚀 Installazione

### Da Git (development mode)

```bash
pip install -e git+https://github.com/rulloizio/ssl-watchdog.git#egg=ssl-watchdog
```

### Localmente (development)

```bash
git clone https://github.com/rulloizio/ssl-watchdog.git
cd ssl-watchdog
pip install -e .
```

## 📖 Utilizzo

### Come CLI

```bash
ssl-watchdog tuosito.com
```

### Come libreria Python

```python
from ssl_watchdog import analizza_dominio

result = analizza_dominio("google.com")
print(result)
```

## 📊 Output

```json
{
  "dominio": "google.com",
  "data_controllo": "2026-06-26T18:30:00+00:00Z",
  "ssl": {
    "valido": true,
    "scadenza": "2026-08-31",
    "giorni_rimasti": 65,
    "errore": null
  },
  "whois": {
    "disponibile": true,
    "registrar": "MarkMonitor, Inc.",
    "name_servers": ["ns1.google.com", "ns2.google.com"],
    "stato": ["clientDeleteProhibited"],
    "creato_il": "1997-09-15",
    "scadenza": "2028-09-14",
    "giorni_rimasti": 810,
    "errore": null
  }
}
```

## 📦 Dipendenze

- Python >= 3.7
- `python-whois >= 0.8.0`

## 🏗️ Architettura

Progetto strutturato con il moderno layout `src/`:

```
ssl-watchdog/
├── pyproject.toml           # Configurazione moderna (PEP 517/518)
├── README.md
└── src/
    └── ssl_watchdog/
        ├── __init__.py      # Espone l'API pubblica
        ├── main.py          # Logica principale + CLI
        ├── _ssl_service.py  # Service SSL
        └── _whois_service.py # Service WHOIS
```

## 👨‍💼 Autore

Patrizio Fanelli

## 📄 Licenza

MIT
