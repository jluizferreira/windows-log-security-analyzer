"""
event_reader.py
---------------
Módulo responsável por ler eventos do Windows Event Log
usando a biblioteca pywin32 (win32evtlog).

Suporta leitura dos logs de Segurança do Windows e retorna
eventos estruturados para análise posterior.
"""

import win32evtlog
import win32evtlogutil
import win32con
import winerror
from datetime import datetime
from typing import Generator


# IDs de eventos monitorados
MONITORED_EVENT_IDS = {
    4624: "Successful Login",
    4625: "Failed Login",
    4720: "User Account Created",
    4726: "User Account Deleted",
}


def read_security_events(max_events: int = 5000) -> list[dict]:
    """
    Lê eventos do log de segurança do Windows (Security Log).

    Args:
        max_events (int): Número máximo de eventos a serem lidos.
                          Default: 5000

    Returns:
        list[dict]: Lista de dicionários com os dados dos eventos relevantes.
                    Cada dicionário contém:
                        - event_id (int)
                        - time_generated (datetime)
                        - source_name (str)
                        - event_data (list)
                        - string_inserts (tuple | None)
    """
    events = []
    server = "localhost"
    log_type = "Security"

    try:
        # Abre o handle para o log de segurança
        handle = win32evtlog.OpenEventLog(server, log_type)
    except Exception as e:
        print(f"[ERROR] Não foi possível abrir o log de segurança: {e}")
        print("        Execute o script como Administrador.")
        return []

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total_read = 0

    try:
        while total_read < max_events:
            # Lê um lote de eventos
            raw_events = win32evtlog.ReadEventLog(handle, flags, 0)

            if not raw_events:
                break  # Não há mais eventos para ler

            for event in raw_events:
                event_id = event.EventID & 0xFFFF  # Mascara para obter o ID real

                # Filtra apenas os eventos de interesse
                if event_id in MONITORED_EVENT_IDS:
                    event_data = {
                        "event_id": event_id,
                        "time_generated": event.TimeGenerated.Format(),
                        "source_name": event.SourceName,
                        "string_inserts": event.StringInserts,
                        "event_category": MONITORED_EVENT_IDS.get(event_id, "Unknown"),
                    }
                    events.append(event_data)

                total_read += 1
                if total_read >= max_events:
                    break

    except Exception as e:
        print(f"[ERROR] Erro ao ler eventos: {e}")
    finally:
        win32evtlog.CloseEventLog(handle)

    return events


def parse_event_time(time_str: str) -> datetime | None:
    """
    Converte a string de tempo retornada pelo pywin32 para um objeto datetime.

    Args:
        time_str (str): String de data/hora no formato do pywin32.

    Returns:
        datetime | None: Objeto datetime ou None em caso de falha.
    """
    try:
        # Formato típico retornado pelo pywin32: '03/11/2024 14:30:45'
        return datetime.strptime(time_str, "%m/%d/%Y %H:%M:%S")
    except ValueError:
        try:
            # Tentativa de formato alternativo
            return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None


def get_event_summary(events: list[dict]) -> dict:
    """
    Gera um resumo rápido da quantidade de eventos por tipo.

    Args:
        events (list[dict]): Lista de eventos lidos.

    Returns:
        dict: Contagem de eventos por event_id.
    """
    summary = {}
    for event in events:
        eid = event["event_id"]
        summary[eid] = summary.get(eid, 0) + 1
    return summary
