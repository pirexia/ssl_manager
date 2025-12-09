from ldap3 import Server, Connection, ALL

try:
    print("Connecting to LDAP server...")
    server = Server('localhost', port=389, get_info=ALL)
    conn = Connection(server, 'cn=admin,dc=sslmanager,dc=local', 'admin123', auto_bind=True)
    print("Connection successful!")
    print(conn)
except Exception as e:
    print(f"Connection failed: {e}")
    import traceback
    traceback.print_exc()
