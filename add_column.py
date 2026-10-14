import psycopg
conn = psycopg.connect('host=127.0.0.1 port=5432 dbname=network_telemetry user=postgres password=Admin123')
cur = conn.cursor()
cur.execute('ALTER TABLE assets ADD COLUMN IF NOT EXISTS discovery_source varchar(32);')
conn.commit()
print('Added discovery_source column')