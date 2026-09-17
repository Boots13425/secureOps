import psycopg

conn = psycopg.connect(
    "host=127.0.0.1 port=5432 dbname=postgres user=postgres password=Admin123",
    autocommit=True
)
cur = conn.cursor()
cur.execute("""
    SELECT pg_terminate_backend(pid)
    FROM pg_stat_activity
    WHERE datname = 'network_telemetry' AND pid <> pg_backend_pid();
""")
cur.execute("DROP DATABASE IF EXISTS network_telemetry;")
cur.execute("CREATE DATABASE network_telemetry;")
print("Done - database reset successfully")
conn.close()