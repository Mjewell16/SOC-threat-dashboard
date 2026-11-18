from datetime import datetime
import pandas as pd

from db import get_connection


def create_incident(
    severity,
    incident_type,
    source_ip,
    failed_attempts,
    mitre,
    username=None,
):
    conn = get_connection()
    cursor = conn.cursor()

    # Check for an existing active incident
    cursor.execute(
        """
        SELECT incident_id
        FROM incidents
        WHERE source_ip = %s
        AND incident_type = %s
        AND status != 'Closed'
        LIMIT 1
        """,
        (source_ip, incident_type),
    )

    existing = cursor.fetchone()

    if existing:
        conn.close()
        return existing[0]

    # Create incident
    cursor.execute(
        """
        INSERT INTO incidents (
            created_at,
            severity,
            incident_type,
            source_ip,
            username,
            failed_attempts,
            status,
            assigned_to,
            mitre_technique
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            datetime.now(),
            severity,
            incident_type,
            source_ip,
            username,
            int(failed_attempts),
            "Open",
            "Unassigned",
            mitre,
        ),
    )

    db_id = cursor.lastrowid
    incident_id = f"INC-{1000 + db_id}"

    cursor.execute(
        """
        UPDATE incidents
        SET incident_id = %s
        WHERE id = %s
        """,
        (incident_id, db_id),
    )

    conn.commit()
    conn.close()

    return incident_id


def get_incidents():
    conn = get_connection()

    query = """
        SELECT
            incident_id,
            created_at,
            severity,
            incident_type,
            source_ip,
            username,
            failed_attempts,
            status,
            assigned_to,
            mitre_technique,
            updated_at
        FROM incidents
        ORDER BY id DESC
    """

    df = pd.read_sql(query, conn)
    conn.close()

    return df


def update_incident_status(incident_id, status):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE incidents
        SET status = %s
        WHERE incident_id = %s
        """,
        (status, incident_id),
    )

    conn.commit()
    conn.close()



def assign_incident(incident_id, analyst):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE incidents
        SET assigned_to = %s
        WHERE incident_id = %s
        """,
        (analyst, incident_id),
    )

    conn.commit()
    conn.close()

def add_incident_note(incident_id, analyst, note):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO incident_notes (
            incident_id,
            analyst,
            note,
            created_at
        )
        VALUES (%s, %s, %s, %s)
        """,
        (
            incident_id,
            analyst,
            note,
            datetime.now(),
        ),
    )

    conn.commit()
    conn.close()


def get_incident_notes(incident_id):
    conn = get_connection()

    query = """
        SELECT
            id,
            incident_id,
            analyst,
            note,
            created_at
        FROM incident_notes
        WHERE incident_id = %s
        ORDER BY created_at DESC
    """

    df = pd.read_sql(
        query,
        conn,
        params=(incident_id,),
    )

    conn.close()

    return df