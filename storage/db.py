import mysql.connector
import config


def get_connection():
    return mysql.connector.connect(
        host     = config.DB_HOST,
        port     = config.DB_PORT,
        database = config.DB_NAME,
        user     = config.DB_USER,
        password = config.DB_PASSWORD,
    )


def insert_vulnerability(conn, r: dict) -> int:
    sql = """
        INSERT INTO vulnerabilities
          (host, port, vuln_id, name, severity, cvss,
           description, remediation, detected_at, raw_hash, status, aged)
        VALUES
          (%(host)s, %(port)s, %(vuln_id)s, %(name)s, %(severity)s, %(cvss)s,
           %(description)s, %(remediation)s, %(detected_at)s, %(raw_hash)s,
           %(status)s, %(aged)s)
    """
    r.setdefault("aged", False)
    r.setdefault("status", "open")
    cursor = conn.cursor()
    cursor.execute(sql, r)
    conn.commit()
    last_id = cursor.lastrowid
    cursor.close()
    return last_id


def insert_event(conn, r: dict) -> int:
    sql = """
        INSERT INTO events
          (host, event_id, event_type, severity, user,
           description, detected_at, raw_hash)
        VALUES
          (%(host)s, %(event_id)s, %(event_type)s, %(severity)s, %(user)s,
           %(description)s, %(detected_at)s, %(raw_hash)s)
    """
    cursor = conn.cursor()
    cursor.execute(sql, r)
    conn.commit()
    last_id = cursor.lastrowid
    cursor.close()
    return last_id


def flag_correlation(conn, c: dict):
    sql = """
        INSERT INTO correlations
          (host, vuln_id, event_id, event_type, vuln_time, event_time, severity)
        VALUES
          (%(host)s, %(vuln_id)s, %(event_id)s, %(event_type)s,
           %(vuln_time)s, %(event_time)s, %(severity)s)
        ON DUPLICATE KEY UPDATE severity = %(severity)s
    """
    cursor = conn.cursor()
    cursor.execute(sql, c)
    conn.commit()
    cursor.close()
