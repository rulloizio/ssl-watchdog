"""
ssl-watchdog: Monitor domain health (SSL certificate and WHOIS data)
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from ._ssl_service import SSLService
from ._whois_service import WhoisService


def analizza_dominio(dominio: str, timeout: int = 10) -> dict:
    """
    Analizza la salute di un dominio (SSL e WHOIS).
    
    Args:
        dominio: Nome del dominio da controllare
        timeout: Timeout per la connessione SSL in secondi
        
    Returns:
        Dizionario con i dati SSL e WHOIS
    """
    # Ottieni la data e ora UTC di controllo
    now_utc = datetime.now(timezone.utc)
    data_controllo = now_utc.replace(microsecond=0).isoformat() + "Z"
    
    # Esegui i controlli
    ssl_service = SSLService(timeout=timeout)
    whois_service = WhoisService()
    
    ssl_info = ssl_service.check_ssl(dominio)
    whois_info = whois_service.check_whois(dominio)
    
    # Costruisci il risultato
    result = {
        "dominio": dominio,
        "data_controllo": data_controllo,
        "ssl": ssl_info.to_dict(),
        "whois": whois_info.to_dict(),
    }
    
    return result


def cli_entrypoint():
    """Entry point per la CLI - gestisce l'input da riga di comando"""
    
    parser = argparse.ArgumentParser(
        description="Controlla la salute di un dominio (SSL e WHOIS)"
    )
    parser.add_argument(
        "dominio",
        help="Nome del dominio da controllare (es. tuosito.com)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout per la connessione SSL in secondi (default: 10)"
    )
    
    args = parser.parse_args()
    
    try:
        # Analizza il dominio
        result = analizza_dominio(args.dominio, timeout=args.timeout)
        
        # Output ESCLUSIVAMENTE JSON in STDOUT
        output_json = json.dumps(result, ensure_ascii=False, indent=2)
        print(output_json)
        
        sys.exit(0)
    
    except Exception as e:
        # Anche in caso di errore, restituisci un JSON con l'errore
        error_json = json.dumps({
            "dominio": args.dominio if hasattr(args, 'dominio') else "unknown",
            "errore": str(e)
        }, ensure_ascii=False, indent=2)
        print(error_json)
        sys.exit(1)


if __name__ == "__main__":
    cli_entrypoint()
