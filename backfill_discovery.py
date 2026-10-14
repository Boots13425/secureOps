import psycopg
conn = psycopg.connect('host=127.0.0.1 port=5432 dbname=network_telemetry user=postgres password=Admin123')
cur = conn.cursor()
cur.execute('UPDATE assets SET discovery_source = %s WHERE discovery_source IS NULL', ('nmap',))
conn.commit()
print(f'Updated {cur.rowcount} assets')
cur.execute('SELECT count(*) FROM assets WHERE discovery_source IS NULL')
print(f'Remaining null: {cur.fetchone()[0]}')