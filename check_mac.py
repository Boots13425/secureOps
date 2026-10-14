import psycopg
conn = psycopg.connect('host=127.0.0.1 port=5432 dbname=network_telemetry user=postgres password=Admin123')
cur = conn.cursor()
cur.execute('SELECT * FROM assets WHERE mac_address = %s', ('f4:3b:d8:d1:60:14',))
rows = cur.fetchall()
for r in rows:
    print(r)
cur.execute('SELECT * FROM snmp_mac_ip_observations WHERE mac_address = %s', ('f4:3b:d8:d1:60:14',))
rows = cur.fetchall()
for r in rows:
    print('SNMP:', r)