import psycopg
conn = psycopg.connect('host=127.0.0.1 port=5432 dbname=network_telemetry user=postgres password=Admin123')
cur = conn.cursor()
cur.execute('ALTER TABLE scan_sessions ADD COLUMN IF NOT EXISTS scan_summary jsonb;')
conn.commit()
print('Added scan_summary column to scan_sessions')