from datetime import datetime, timezone
from typing import List, Optional, Union
import whois


class WhoisInfo:
    """Contenitore per i dati WHOIS"""
    def __init__(self, disponibile: bool, registrar: Optional[str] = None,
                 name_servers: Optional[List[str]] = None, stato: Optional[List[str]] = None,
                 creato_il: Optional[str] = None, scadenza: Optional[str] = None,
                 giorni_rimasti: Optional[int] = None, errore: Optional[str] = None):
        self.disponibile = disponibile
        self.registrar = registrar
        self.name_servers = name_servers or []
        self.stato = stato
        self.creato_il = creato_il
        self.scadenza = scadenza
        self.giorni_rimasti = giorni_rimasti
        self.errore = errore

    def to_dict(self):
        return {
            "disponibile": self.disponibile,
            "registrar": self.registrar,
            "name_servers": self.name_servers,
            "stato": self.stato,
            "creato_il": self.creato_il,
            "scadenza": self.scadenza,
            "giorni_rimasti": self.giorni_rimasti,
            "errore": self.errore,
        }


class WhoisService:
    """Service per interrogare i dati WHOIS del dominio"""

    def check_whois(self, dominio: str) -> WhoisInfo:
        """Controlla i dati WHOIS del dominio."""
        try:
            whois_data = whois.whois(dominio)
            
            if not whois_data:
                return WhoisInfo(disponibile=False, errore="Dati WHOIS non disponibili")
            
            registrar = self._get_field(whois_data, "registrar")
            name_servers = self._get_name_servers(whois_data)
            stato = self._get_status(whois_data)
            creato_il = self._format_date(self._get_field(whois_data, "creation_date"))
            scadenza = self._format_date(self._get_field(whois_data, "expiration_date"))
            giorni_rimasti = self._calculate_days_remaining(self._get_field(whois_data, "expiration_date"))
            
            return WhoisInfo(
                disponibile=True,
                registrar=registrar,
                name_servers=name_servers,
                stato=stato,
                creato_il=creato_il,
                scadenza=scadenza,
                giorni_rimasti=giorni_rimasti,
                errore=None
            )
        
        except whois.parser.PywhoisError as e:
            return WhoisInfo(disponibile=False, errore=f"Errore WHOIS: {str(e)}")
        except Exception as e:
            return WhoisInfo(disponibile=False, errore=f"Errore durante la query WHOIS: {str(e)}")

    @staticmethod
    def _get_field(whois_data: dict, field_name: str) -> Optional[Union[str, List]]:
        """Estrae un campo dai dati WHOIS, gestendo le liste"""
        value = whois_data.get(field_name)
        if value is None:
            return None
        if isinstance(value, list) and len(value) > 0:
            return value[0]
        return value if value else None

    @staticmethod
    def _get_name_servers(whois_data: dict) -> List[str]:
        """Estrae i name server dal WHOIS, gestendo newline al loro interno"""
        ns = whois_data.get("name_servers")
        if not ns:
            return []
        
        result = []
        if isinstance(ns, list):
            for n in ns:
                if n:
                    items = str(n).split('\n')
                    for item in items:
                        cleaned = item.strip().lower()
                        if cleaned:
                            result.append(cleaned)
        else:
            items = str(ns).split('\n')
            for item in items:
                cleaned = item.strip().lower()
                if cleaned:
                    result.append(cleaned)
        
        return result

    @staticmethod
    def _get_status(whois_data: dict) -> Optional[List[str]]:
        """Estrae lo stato del dominio dal WHOIS"""
        status = whois_data.get("status")
        if not status:
            return None
        if isinstance(status, list):
            return [str(s).strip() for s in status if s]
        return [str(status).strip()]

    @staticmethod
    def _format_date(date_value: Optional[Union[str, datetime]]) -> Optional[str]:
        """Formatta una data nel formato YYYY-MM-DD"""
        if date_value is None:
            return None
        try:
            if isinstance(date_value, datetime):
                return date_value.strftime("%Y-%m-%d")
            elif isinstance(date_value, str):
                parsed = datetime.fromisoformat(date_value.replace("Z", "+00:00"))
                return parsed.strftime("%Y-%m-%d")
        except Exception:
            pass
        return None

    @staticmethod
    def _calculate_days_remaining(date_value: Optional[Union[str, datetime]]) -> Optional[int]:
        """Calcola i giorni rimasti fino alla scadenza"""
        if date_value is None:
            return None
        try:
            if isinstance(date_value, str):
                date_value = datetime.fromisoformat(date_value.replace("Z", "+00:00"))
            if isinstance(date_value, datetime):
                if date_value.tzinfo is None:
                    date_value = date_value.replace(tzinfo=timezone.utc)
                ora_utc = datetime.now(timezone.utc)
                return (date_value - ora_utc).days
        except Exception:
            pass
        return None
