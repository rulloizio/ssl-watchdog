import socket
import ssl
from datetime import datetime, timezone
from typing import Optional, Union


class SSLInfo:
    """Contenitore per i dati SSL"""
    def __init__(self, valido: bool, scadenza: Optional[str] = None, 
                 giorni_rimasti: Optional[int] = None, errore: Optional[str] = None):
        self.valido = valido
        self.scadenza = scadenza
        self.giorni_rimasti = giorni_rimasti
        self.errore = errore

    def to_dict(self):
        return {
            "valido": self.valido,
            "scadenza": self.scadenza,
            "giorni_rimasti": self.giorni_rimasti,
            "errore": self.errore,
        }


class SSLService:
    """Service per controllare la validità e scadenza del certificato SSL"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def check_ssl(self, dominio: str) -> SSLInfo:
        """Controlla il certificato SSL del dominio."""
        try:
            cert = self._get_ssl_cert(dominio)
            
            if not cert:
                return SSLInfo(
                    valido=False,
                    scadenza=None,
                    giorni_rimasti=None,
                    errore="Certificato non trovato"
                )
            
            scadenza_str = cert.get("notAfter")
            if not scadenza_str:
                return SSLInfo(
                    valido=False,
                    scadenza=None,
                    giorni_rimasti=None,
                    errore="Data di scadenza non trovata nel certificato"
                )
            
            scadenza_dt = datetime.strptime(scadenza_str, "%b %d %H:%M:%S %Y %Z")
            scadenza_dt = scadenza_dt.replace(tzinfo=timezone.utc)
            
            ora_utc = datetime.now(timezone.utc)
            giorni_rimasti = (scadenza_dt - ora_utc).days
            scadenza_formattata = scadenza_dt.strftime("%Y-%m-%d")
            
            return SSLInfo(
                valido=giorni_rimasti > 0,
                scadenza=scadenza_formattata,
                giorni_rimasti=giorni_rimasti,
                errore=None
            )
        
        except socket.timeout:
            return SSLInfo(
                valido=False, scadenza=None, giorni_rimasti=None,
                errore="Timeout durante la connessione SSL"
            )
        except ConnectionRefusedError:
            return SSLInfo(
                valido=False, scadenza=None, giorni_rimasti=None,
                errore="Connessione rifiutata sulla porta 443"
            )
        except Exception as e:
            return SSLInfo(
                valido=False, scadenza=None, giorni_rimasti=None,
                errore=f"Errore SSL: {str(e)}"
            )

    def _get_ssl_cert(self, dominio: str) -> Optional[dict]:
        """Estrae il certificato SSL dal dominio"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((dominio, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                    return ssock.getpeercert()
        except Exception:
            return None
