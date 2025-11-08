#!/usr/bin/env python3
"""
CLI Order Manager (single-file) - upgraded

Features:
- ROLE: customer
- LOGIN / SIGNUP (username + password) with collision detection
- CRUD for orders stored in SQLite (external DB file)
- Track order: prints a Google Maps directions link (origin -> destination)
- Place new order with filters: Origin, Destination, Weight (numeric)
- Mark order DONE (tick)
- Arrow-key (↑/↓) interactive menu (curses) and Enter to select
- Finite State Machine to manage CLI states
- Passwords stored as salted SHA-256 hashes (demo-grade)
- Auto-migrates old schema (country/company -> origin/destination) if present
"""

import os, sys, sqlite3, getpass, hashlib, uuid, urllib.parse, datetime, shutil
from contextlib import closing

DB_PATH = os.path.join(os.path.dirname(__file__), 'cli_orders.db')

# ----------- Utilities & DB ----------------

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def table_columns(conn, table_name):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table_name})")
    return [r['name'] for r in cur.fetchall()]

def init_db():
    """
    Initializes DB. If old columns 'country'/'company' exist, migrate to 'origin'/'destination'.
    """
    need_migration = False
    conn = get_conn()
    cur = conn.cursor()

    # Ensure users table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')

    # If orders doesn't exist create with new schema
    cur.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        origin TEXT,
        destination TEXT,
        weight REAL,
        done INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()

    # Check for old schema columns 'country'/'company' (rare if DB created before)
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='orders_old_schema_check'")
    # we'll inspect current orders columns
    cols = table_columns(conn, 'orders')
    # If columns contain 'country' or 'company', we assume legacy DB and try to migrate.
    if 'country' in cols or 'company' in cols:
        need_migration = True

    if need_migration:
        print("Migrating old 'country/company' columns to 'origin/destination'...")

        # create a backup
        backup = DB_PATH + '.bak'
        shutil.copy2(DB_PATH, backup)

        # create new table
        cur.execute('''
        CREATE TABLE IF NOT EXISTS orders_new (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            origin TEXT,
            destination TEXT,
            weight REAL,
            done INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')

        # try to copy from old columns to new columns when available
        # determine available columns
        old_cols = cols
        select_cols = []
        mapping = []
        # id, user_id always expected
        select_cols.append('id')
        select_cols.append('user_id')
        if 'country' in old_cols:
            select_cols.append('country')
            mapping.append(('country', 'origin'))
        else:
            mapping.append((None, 'origin'))
        if 'company' in old_cols:
            select_cols.append('company')
            mapping.append(('company', 'destination'))
        else:
            mapping.append((None, 'destination'))
        if 'weight' in old_cols:
            select_cols.append('weight')
        if 'done' in old_cols:
            select_cols.append('done')
        if 'created_at' in old_cols:
            select_cols.append('created_at')
        else:
            select_cols.append(f"'{datetime.datetime.utcnow().isoformat()}' as created_at")
        # Build query
        sel = ', '.join(select_cols)
        try:
            rows = cur.execute(f"SELECT {sel} FROM orders").fetchall()
            for r in rows:
                oid = r['id']
                uid = r['user_id']
                origin = r['country'] if 'country' in r.keys() and r['country'] is not None else None
                destination = r['company'] if 'company' in r.keys() and r['company'] is not None else None
                weight = r['weight'] if 'weight' in r.keys() else None
                done = r['done'] if 'done' in r.keys() else 0
                created_at = r['created_at'] if 'created_at' in r.keys() else datetime.datetime.utcnow().isoformat()
                cur.execute('INSERT OR REPLACE INTO orders_new (id, user_id, origin, destination, weight, done, created_at) VALUES (?,?,?,?,?,?,?)',
                            (oid, uid, origin, destination, weight, done, created_at))
            conn.commit()
            # drop old table, rename new
            cur.execute('DROP TABLE orders')
            cur.execute('ALTER TABLE orders_new RENAME TO orders')
            conn.commit()
            print("Migration complete. Backup saved to:", backup)
        except Exception as e:
            print("Automatic migration failed:", e)
            print("Your DB has been backed up as:", backup)
            print("Please inspect/upgrade manually.")
    conn.close()

def hash_password(password, salt=None):
    if salt is None:
        salt = uuid.uuid4().hex
    h = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return h, salt

# ----------- CRUD & Operations ----------------

def signup():
    conn = get_conn(); cur = conn.cursor()
    print('\nSignup (create new customer)')
    name = input('Full name: ').strip()
    while True:
        username = input('Choose username: ').strip()
        if not username:
            print('Username cannot be blank.')
            continue
        cur.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        if cur.fetchone():
            print('That username already exists — collision detected. Try another.')
        else:
            break
    while True:
        password = getpass.getpass('Password: ')
        confirm = getpass.getpass('Confirm password: ')
        if password != confirm:
            print('Passwords do not match. Try again.')
        elif len(password) < 4:
            print('Password too short; use at least 4 characters.')
        else:
            break
    pwd_hash, salt = hash_password(password)
    user_id = uuid.uuid4().hex
    cur.execute('INSERT INTO users (id, name, username, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (user_id, name, username, pwd_hash, salt, datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    print('Signup successful — you can now login.')

def login():
    conn = get_conn(); cur = conn.cursor()
    print('\nLogin')
    username = input('Username: ').strip()
    password = getpass.getpass('Password: ')
    cur.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    if not row:
        print('No such user.')
        conn.close()
        return None
    stored_hash = row['password_hash']; salt = row['salt']
    h, _ = hash_password(password, salt=salt)
    if h != stored_hash:
        print('Incorrect password.')
        conn.close()
        return None
    conn.close()
    print(f'Welcome back, {row["name"]}!')
    return dict(row)

def ensure_logged_in(user):
    if not user:
        print('You must be logged in to do that.')
        return False
    return True

def create_order(user):
    conn = get_conn(); cur = conn.cursor()
    print('\nPlace new order (filters will be applied as you like)')
    origin = input('Origin (filterable): ').strip()
    destination = input('Destination (filterable): ').strip()
    while True:
        weight_s = input('Weight (numeric) : ').strip()
        try:
            weight = float(weight_s)
            break
        except Exception:
            print('Enter a valid number for weight.')
    order_id = uuid.uuid4().hex
    now = datetime.datetime.utcnow().isoformat()
    cur.execute('INSERT INTO orders (id, user_id, origin, destination, weight, done, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)',
                (order_id, user['id'], origin, destination, weight, now))
    conn.commit(); conn.close()
    print(f'Order created (id: {order_id[:8]})')

def list_orders(user):
    conn = get_conn(); cur = conn.cursor()
    cur.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', (user['id'],))
    rows = cur.fetchall()
    if not rows:
        print('\nNo orders found.')
    else:
        print('\nYour orders:')
        for r in rows:
            done = '✔' if r['done'] else '✖'
            print(f"- id:{r['id'][:8]} | origin:{r['origin'] or '-'} | destination:{r['destination'] or '-'} | {r['weight']}kg | done:{done}")
    conn.close()

def track_order(user):
    conn = get_conn(); cur = conn.cursor()
    oid = input('Enter order id (first 8 chars is okay): ').strip()
    if len(oid) == 8:
        cur.execute('SELECT * FROM orders WHERE user_id = ? AND substr(id,1,8)=?', (user['id'], oid))
    else:
        cur.execute('SELECT * FROM orders WHERE user_id = ? AND id = ?', (user['id'], oid))
    r = cur.fetchone()
    if not r:
        print('Order not found.')
        conn.close(); return
    origin = r['origin'] or ''
    destination = r['destination'] or ''
    if origin.strip() and destination.strip():
        q_origin = urllib.parse.quote(origin)
        q_dest = urllib.parse.quote(destination)
        maps_link = f'https://www.google.com/maps/dir/?api=1&origin={q_origin}&destination={q_dest}'
        print('\nGoogle Maps directions (shortest path) from origin -> destination:')
        print(maps_link)
        print('\n(Open the URL in a browser to view the route on Google Maps.)')
    elif destination.strip():
        # fallback: if no origin, show search to destination
        q = urllib.parse.quote(destination)
        maps_link = f'https://www.google.com/maps/search/?api=1&query={q}'
        print('\nNo origin recorded. Showing search link for destination:')
        print(maps_link)
    else:
        print('No origin or destination recorded for this order.')
    conn.close()

def update_order(user):
    conn = get_conn(); cur = conn.cursor()
    oid = input('Enter order id to update (first 8 chars ok): ').strip()
    if len(oid)==8:
        cur.execute('SELECT * FROM orders WHERE user_id = ? AND substr(id,1,8)=?', (user['id'], oid))
    else:
        cur.execute('SELECT * FROM orders WHERE user_id = ? AND id = ?', (user['id'], oid))
    r = cur.fetchone()
    if not r:
        print('Order not found.'); conn.close(); return
    print('Leave field blank to keep current value.')
    origin = input(f'Origin [{r["origin"] or "-"}]: ').strip() or r['origin']
    destination = input(f'Destination [{r["destination"] or "-"}]: ').strip() or r['destination']
    while True:
        w = input(f'Weight [{r["weight"]}]: ').strip()
        if not w:
            weight = r['weight']; break
        try:
            weight = float(w); break
        except:
            print('Enter numeric weight.')
    done_in = input(f'Mark as done? (y/N) [{ "Y" if r["done"] else "N" }]: ').strip().lower()
    done = 1 if done_in == 'y' else r['done']
    now = datetime.datetime.utcnow().isoformat()
    cur.execute('UPDATE orders SET origin=?, destination=?, weight=?, done=?, updated_at=? WHERE id=?',
                (origin, destination, weight, done, now, r['id']))
    conn.commit(); conn.close()
    print('Order updated.')

def delete_order(user):
    conn = get_conn(); cur = conn.cursor()
    oid = input('Enter order id to delete (first 8 chars ok): ').strip()
    if len(oid)==8:
        cur.execute('SELECT id FROM orders WHERE user_id = ? AND substr(id,1,8)=?', (user['id'], oid))
    else:
        cur.execute('SELECT id FROM orders WHERE user_id = ? AND id = ?', (user['id'], oid))
    r = cur.fetchone()
    if not r:
        print('Order not found.'); conn.close(); return
    confirm = input('Type "delete" to confirm deletion: ').strip().lower()
    if confirm == 'delete':
        cur.execute('DELETE FROM orders WHERE id = ?', (r['id'],))
        conn.commit()
        print('Order deleted.')
    else:
        print('Deletion cancelled.')
    conn.close()

def demo_run():
    """Non-interactive demo to show DB usage."""
    init_db()
    conn = get_conn(); cur = conn.cursor()
    # create demo user if not exists
    cur.execute('SELECT * FROM users WHERE username = ?', ('demo',))
    row = cur.fetchone()
    if not row:
        pwd_hash, salt = hash_password('demo123')
        user_id = uuid.uuid4().hex
        cur.execute('INSERT INTO users (id, name, username, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                    (user_id, 'Demo User', 'demo', pwd_hash, salt, datetime.datetime.utcnow().isoformat()))
        conn.commit()
        cur.execute('SELECT * FROM users WHERE username = ?', ('demo',))
        row = cur.fetchone()
    u = dict(row)
    print('Demo user:', u['username'], 'id', u['id'][:8])
    # create an order
    cur.execute('INSERT INTO orders (id, user_id, origin, destination, weight, done, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)',
                (uuid.uuid4().hex, u['id'], 'Connaught Place, New Delhi, India', 'IGI Airport, New Delhi, India', 12.5, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    print('Inserted demo order.')
    # list orders
    rows = cur.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', (u['id'],)).fetchall()
    print('\nList of orders for demo user:')
    for r in rows:
        print(f"- {r['id'][:8]} | origin:{r['origin']} | destination:{r['destination']} | {r['weight']}kg | done:{r['done']}")
    # show maps link for latest order
    latest = rows[0]
    qo = urllib.parse.quote(latest['origin'])
    qd = urllib.parse.quote(latest['destination'])
    maps_link = f'https://www.google.com/maps/dir/?api=1&origin={qo}&destination={qd}'
    print('\nMaps directions link for the latest order:')
    print(maps_link)
    conn.close()

# ----------- Curses arrow menu ----------------
# We'll run only the menu rendering in curses; after selection we return to normal terminal IO.
# This keeps getpass/input safe.

def curses_menu(options, title=None, footer=None):
    """
    Display a vertical menu using curses. Returns the index of the chosen option.
    """
    try:
        import curses
    except Exception as e:
        # If curses not available, fallback to simple numbered input
        print("Terminal doesn't support curses; falling back to numbered menu.")
        if title:
            print(title)
        for i, opt in enumerate(options, 1):
            print(f"{i}) {opt}")
        while True:
            choice = input("Choose: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(options):
                return int(choice)-1
            else:
                print("Invalid option.")
    else:
        def _curses(stdscr):
            curses.curs_set(0)
            stdscr.keypad(True)
            current = 0
            while True:
                stdscr.clear()
                h, w = stdscr.getmaxyx()
                y = 1
                if title:
                    stdscr.addstr(y, 2, title)
                    y += 2
                for i, opt in enumerate(options):
                    prefix = "→ " if i == current else "  "
                    if i == current:
                        try:
                            stdscr.addstr(y + i, 4, prefix + opt, curses.A_REVERSE | curses.A_BOLD)
                        except:
                            stdscr.addstr(y + i, 4, prefix + opt)
                    else:
                        stdscr.addstr(y + i, 4, prefix + opt)
                if footer:
                    stdscr.addstr(h-2, 2, footer)
                key = stdscr.getch()
                if key in (curses.KEY_UP, ord('k')):
                    if current > 0: current -= 1
                elif key in (curses.KEY_DOWN, ord('j')):
                    if current < len(options)-1: current += 1
                elif key in (10, 13):  # Enter
                    return current
                elif key in (ord('q'), 27):  # q or Esc
                    return None
        idx = None
        try:
            idx = curses.wrapper(_curses)
        except Exception as e:
            # fallback to simple menu
            print("Curses menu failed; falling back to simple numbered menu.")
            if title:
                print(title)
            for i, opt in enumerate(options, 1):
                print(f"{i}) {opt}")
            while True:
                choice = input("Choose: ").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(options):
                    return int(choice)-1
                else:
                    print("Invalid option.")
        return idx

# ----------- FSM Driven Interactive Loop ----------------

def interactive_loop():
    init_db()
    user = None

    # states
    STATE_MAIN = 'main'
    STATE_LOGGED = 'logged'
    STATE_EXIT = 'exit'

    state = STATE_MAIN

    while state != STATE_EXIT:
        if state == STATE_MAIN:
            options = ['Signup', 'Login', 'Quit']
            idx = curses_menu(options, title="--- CLI Order Manager --- (use ↑/↓ and Enter; q to quit)")
            # If user pressed Esc/q in curses, idx is None -> treat as Quit
            if idx is None or idx == 3:
                print("Goodbye."); state = STATE_EXIT; continue
            choice = options[idx]
            if choice == 'Signup':
                signup()
            elif choice == 'Login':
                user = login() or user
                if user:
                    state = STATE_LOGGED
            elif choice == 'Demo (seed & show)':
                demo_run()
            elif choice == 'Quit':
                state = STATE_EXIT

        elif state == STATE_LOGGED:
            header = f'Logged in: {user["username"]} ({user["name"]})'
            options = ['Place order', 'List my orders', 'Track order (maps directions)', 'Update order', 'Delete order', 'Logout', 'Back to main']
            idx = curses_menu(options, title=header, footer="Navigate with arrows. Enter to select. q to go back.")
            if idx is None:
                # treat as back to main
                state = STATE_MAIN
                continue
            choice = options[idx]
            if choice == 'Place order':
                if ensure_logged_in(user): create_order(user)
            elif choice == 'List my orders':
                if ensure_logged_in(user): list_orders(user)
            elif choice == 'Track order (maps directions)':
                if ensure_logged_in(user): track_order(user)
            elif choice == 'Update order':
                if ensure_logged_in(user): update_order(user)
            elif choice == 'Delete order':
                if ensure_logged_in(user): delete_order(user)
            elif choice == 'Logout':
                user = None; print('Logged out.'); state = STATE_MAIN
            elif choice == 'Back to main':
                state = STATE_MAIN

    print("Exited.")

# ----------- Entrypoint ----------------

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'demo':
        demo_run()
        sys.exit(0)
    try:
        interactive_loop()
    except KeyboardInterrupt:
        print("\nInterrupted. Bye.")
