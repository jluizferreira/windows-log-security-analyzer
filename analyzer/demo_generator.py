"""
demo_generator.py
-----------------
Gerador de eventos simulados para o modo demonstração.

Cria um conjunto realista de eventos de segurança fictícios que
cobrem todos os cenários detectáveis pela ferramenta:
  - Logins normais bem-sucedidos
  - Falhas de login esparsas
  - Ataque de brute force em andamento
  - Criação e exclusão de contas suspeitas

Nenhum dado real do sistema é utilizado neste modo.
"""

from datetime import datetime, timedelta
import random


def generate_demo_events() -> list[dict]:
    """
    Gera uma lista de eventos de segurança simulados.

    Cenários incluídos:
        1. Logins normais de usuários do dia a dia
        2. Algumas falhas esporádicas (usuário esqueceu a senha)
        3. Ataque de brute force contra 'administrator'
        4. Ataque de brute force contra 'backup_service'
        5. Criação de um usuário suspeito
        6. Exclusão de um usuário

    Returns:
        list[dict]: Lista de eventos no mesmo formato retornado
                    pelo event_reader.read_security_events().
    """
    events = []
    now = datetime.now()

    # ── Helpers internos ──────────────────────────────────────────────

    def fmt(dt: datetime) -> str:
        """Formata datetime para o padrão usado pelo event_reader."""
        return dt.strftime("%m/%d/%Y %H:%M:%S")

    def login_ok(username: str, delta_minutes: int = 0) -> dict:
        """Cria um evento 4624 (login bem-sucedido)."""
        t = now - timedelta(minutes=delta_minutes)
        return {
            "event_id": 4624,
            "time_generated": fmt(t),
            "source_name": "Microsoft-Windows-Security-Auditing",
            "event_category": "Successful Login",
            # StringInserts: índice 5 = username, índice 6 = domain
            "string_inserts": (
                "-", "-", "-", "-", "-",
                username, "WORKGROUP", "-", "3",
                "-", "-", "-", "-", "-", "-",
                "-", "-", "-", "192.168.1.10",
            ),
        }

    def login_fail(username: str, delta_minutes: int = 0, source_ip: str = "192.168.1.50") -> dict:
        """Cria um evento 4625 (falha de login)."""
        t = now - timedelta(minutes=delta_minutes)
        return {
            "event_id": 4625,
            "time_generated": fmt(t),
            "source_name": "Microsoft-Windows-Security-Auditing",
            "event_category": "Failed Login",
            # StringInserts: índice 5 = username, índice 19 = source_ip
            "string_inserts": (
                "-", "-", "-", "-", "-",
                username, "WORKGROUP", "-", "-",
                "%%2313 Unknown user name or bad password",
                "3", "-", "-", "-", "-",
                "-", "-", "-", "-", source_ip,
            ),
        }

    def user_created(new_user: str, created_by: str, delta_minutes: int = 0) -> dict:
        """Cria um evento 4720 (novo usuário criado)."""
        t = now - timedelta(minutes=delta_minutes)
        return {
            "event_id": 4720,
            "time_generated": fmt(t),
            "source_name": "Microsoft-Windows-Security-Auditing",
            "event_category": "User Account Created",
            # StringInserts: índice 0 = new_user, índice 4 = actor
            "string_inserts": (
                new_user, "WORKGROUP", "-", "-",
                created_by, "WORKGROUP",
            ),
        }

    def user_deleted(del_user: str, deleted_by: str, delta_minutes: int = 0) -> dict:
        """Cria um evento 4726 (usuário deletado)."""
        t = now - timedelta(minutes=delta_minutes)
        return {
            "event_id": 4726,
            "time_generated": fmt(t),
            "source_name": "Microsoft-Windows-Security-Auditing",
            "event_category": "User Account Deleted",
            # StringInserts: índice 0 = deleted_user, índice 4 = actor
            "string_inserts": (
                del_user, "WORKGROUP", "-", "-",
                deleted_by, "WORKGROUP",
            ),
        }

    # ── Cenário 1: Logins normais ao longo do dia ─────────────────────
    normal_users = ["joao.silva", "maria.souza", "pedro.alves", "ana.lima", "carlos.santos"]
    for i, user in enumerate(normal_users):
        # Cada usuário faz entre 10 e 30 logins normais
        for j in range(random.randint(10, 30)):
            events.append(login_ok(user, delta_minutes=random.randint(0, 480)))

    # ── Cenário 2: Falhas esporádicas (usuário esqueceu a senha) ──────
    events.append(login_fail("joao.silva",    delta_minutes=240, source_ip="192.168.1.11"))
    events.append(login_fail("joao.silva",    delta_minutes=239, source_ip="192.168.1.11"))
    events.append(login_fail("joao.silva",    delta_minutes=238, source_ip="192.168.1.11"))
    events.append(login_ok  ("joao.silva",    delta_minutes=237))  # conseguiu na quarta tentativa

    events.append(login_fail("maria.souza",   delta_minutes=300, source_ip="192.168.1.22"))
    events.append(login_ok  ("maria.souza",   delta_minutes=299))

    # ── Cenário 3: Brute force contra 'administrator' (externo) ───────
    # 14 tentativas em 3 minutos vindo de IP externo suspeito
    bf_ip_admin = "203.0.113.47"  # IP de exemplo (bloco de documentação RFC 5737)
    for i in range(14):
        # Intervalo de ~13 segundos entre cada tentativa
        events.append(login_fail("administrator", delta_minutes=60, source_ip=bf_ip_admin))

    # ── Cenário 4: Brute force contra 'backup_service' ────────────────
    # 8 tentativas em 2 minutos — outro IP
    bf_ip_svc = "198.51.100.23"
    for i in range(8):
        events.append(login_fail("backup_service", delta_minutes=30, source_ip=bf_ip_svc))

    # ── Cenário 5: Criação de usuário suspeito às 03h da manhã ────────
    # (delta_minutes=420 = 7 horas atrás, simulando madrugada)
    events.append(user_created("hacker_temp01", "administrator", delta_minutes=420))

    # ── Cenário 6: Exclusão de um usuário legítimo ────────────────────
    events.append(user_deleted("carlos.santos", "administrator", delta_minutes=15))

    # Embaralha para simular ordem real de chegada dos eventos
    random.shuffle(events)

    return events


def print_demo_notice():
    """Exibe um aviso claro de que o modo demo está ativo."""
    notice = """
  ╔══════════════════════════════════════════════════════════════╗
  ║   ⚠️   MODO DEMONSTRAÇÃO ATIVO  —  DADOS SIMULADOS   ⚠️     ║
  ║                                                              ║
  ║  Os eventos abaixo são FICTÍCIOS e gerados localmente.       ║
  ║  Para analisar seu sistema real, execute sem --demo.         ║
  ╚══════════════════════════════════════════════════════════════╝
"""
    print(notice)
