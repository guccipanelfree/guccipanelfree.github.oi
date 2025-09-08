# app.py
from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3, os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import math

app = Flask(__name__)
app.secret_key = 'gucci_secret_key'  # change this before production
DB_FILE = 'guccipanel.db'

def init_db():
    created = not os.path.exists(DB_FILE)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            coins INTEGER DEFAULT 0,
            diamonds INTEGER DEFAULT 0,
            wallet REAL DEFAULT 0,
            vip_until TEXT,
            ads_watched INTEGER DEFAULT 0,
            followers INTEGER DEFAULT 0,
            likes INTEGER DEFAULT 0,
            views INTEGER DEFAULT 0,
            subscribers INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            txn_id TEXT UNIQUE,
            product TEXT,
            quantity INTEGER,
            amount REAL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            service_key TEXT,
            service_label TEXT,
            option_type TEXT,
            quantity INTEGER,
            cost REAL,
            currency TEXT,
            target_link TEXT,
            status TEXT DEFAULT 'Processing',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT,
            amount REAL,
            details TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            reward_type TEXT,
            reward_value INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS support_chat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            message TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            seen INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    if created:
        # initial admin user
        hashed = generate_password_hash('GucciAdmin8240')
        c.execute("INSERT OR IGNORE INTO users (email, password, coins, diamonds, wallet, vip_until) VALUES (?,?,?,?,?,?)",
                  ('guccieditz1@gmail.com', hashed, 0, 99999, 0.0, (datetime.now()+timedelta(days=365)).strftime('%Y-%m-%d')))
        conn.commit()
    conn.close()

init_db()

# Pricing table
PRICE_TABLE = {
    'ig_followers_refill': {'label':'Instagram Followers (Refill)','unit':100,'per_unit_diamonds':5,'per_unit_gold':12,'per_unit_rupees':12.5},
    'ig_followers_perm':   {'label':'Instagram Followers (Permanent)','unit':100,'per_unit_diamonds':10,'per_unit_gold':20,'per_unit_rupees':20},
    'ig_likes':            {'label':'Instagram Likes','unit':100,'per_unit_diamonds':3,'per_unit_gold':5,'per_unit_rupees':5},
    'ig_views':            {'label':'Instagram Views','unit':1000,'per_unit_diamonds':1,'per_unit_gold':2,'per_unit_rupees':2},
    'yt_subs_refill':      {'label':'YouTube Subscribers (Refill)','unit':100,'per_unit_diamonds':8,'per_unit_gold':20,'per_unit_rupees':20},
    'yt_subs_perm':        {'label':'YouTube Subscribers (Permanent)','unit':100,'per_unit_diamonds':12,'per_unit_gold':30,'per_unit_rupees':30},
    'yt_likes':            {'label':'YouTube Likes','unit':100,'per_unit_diamonds':4,'per_unit_gold':5,'per_unit_rupees':5},
    'yt_views':            {'label':'YouTube Views','unit':1000,'per_unit_diamonds':1,'per_unit_gold':2,'per_unit_rupees':2},
}

def compute_cost(service_key, quantity):
    p = PRICE_TABLE.get(service_key)
    if not p:
        return None
    unit = p.get('unit',100)
    batches = math.ceil(quantity / unit)
    return {
        'diamonds': batches * p.get('per_unit_diamonds',0),
        'gold': batches * p.get('per_unit_gold',0),
        'rupees': batches * p.get('per_unit_rupees',0)
    }

def apply_service_to_user(email, service_key, quantity):
    col_map = {
        'ig_followers_refill':'followers',
        'ig_followers_perm':'followers',
        'ig_likes':'likes',
        'ig_views':'views',
        'yt_subs_refill':'subscribers',
        'yt_subs_perm':'subscribers',
        'yt_likes':'likes',
        'yt_views':'views'
    }
    col = col_map.get(service_key)
    if not col:
        return False
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(f"UPDATE users SET {col} = {col} + ? WHERE email=?", (quantity, email))
    conn.commit()
    conn.close()
    return True

def auto_update_orders():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    one_hour_ago = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute("SELECT id, user_email, service_key, quantity FROM orders WHERE status='Processing' AND created_at <= ?", (one_hour_ago,))
    rows = c.fetchall()
    for r in rows:
        oid, email, skey, qty = r
        try:
            apply_service_to_user(email, skey, qty)
        except:
            pass
        c.execute("UPDATE orders SET status='Completed' WHERE id=?", (oid,))
        c.execute("INSERT INTO notifications (user_email, message) VALUES (?,?)", (email, f"Your order #{oid} has been automatically completed." ))
        # log transaction (user id)
        c.execute("SELECT id FROM users WHERE email=?", (email,))
        uid_row = c.fetchone()
        uid = uid_row[0] if uid_row else None
        if uid:
            c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (uid, 'Order Auto-Complete', 0, f'Order #{oid} auto-completed'))
    conn.commit()
    conn.close()

# -------------------- Routes --------------------

@app.route('/')
def index():
    return redirect('/dashboard') if 'user' in session else redirect('/login')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']
        conn = sqlite3.connect(DB_FILE); c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone(); conn.close()
        if user and check_password_hash(user[2], password):
            session['user'] = email
            flash('Logged in','success')
            return redirect('/dashboard')
        flash('Invalid credentials','danger')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        email = request.form['email'].strip()
        password = request.form['password']
        hashed = generate_password_hash(password)
        try:
            conn = sqlite3.connect(DB_FILE); c = conn.cursor()
            c.execute("INSERT INTO users (email,password) VALUES (?,?)", (email, hashed))
            conn.commit(); conn.close()
            flash('Registered. Please login.','success')
            return redirect('/login')
        except Exception as e:
            flash('User exists or error','danger')
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    auto_update_orders()
    email = session['user']
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=?", (email,))
    user = c.fetchone(); conn.close()
    vip_active = False
    try:
        vip_active = bool(user[6] and datetime.strptime(user[6], '%Y-%m-%d') >= datetime.now())
    except:
        vip_active = False
    return render_template('dashboard.html', user=user, vip_active=vip_active)

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out','info')
    return redirect('/login')

# Wallet + payments submitted by users
@app.route('/wallet')
def wallet():
    if 'user' not in session:
        return redirect('/login')
    email = session['user']
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=?", (email,))
    user = c.fetchone()
    c.execute("SELECT id, type, amount, details, date FROM transactions WHERE user_id=(SELECT id FROM users WHERE email=?) ORDER BY date DESC", (email,))
    txns = c.fetchall()
    c.execute("SELECT id, txn_id, product, quantity, amount, status, created_at FROM payments WHERE user_id=(SELECT id FROM users WHERE email=?) ORDER BY created_at DESC", (email,))
    payments = c.fetchall()
    conn.close()
    return render_template('wallet.html', user=user, transactions=txns, payments=payments)

@app.route('/submit_payment', methods=['POST'])
def submit_payment():
    if 'user' not in session:
        return redirect('/login')
    txn_id = request.form['txn_id']
    product = request.form['product']
    amount = float(request.form['amount'])
    quantity = int(request.form.get('quantity', 0))
    email = session['user']
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email=?", (email,))
    uid = c.fetchone()[0]
    try:
        c.execute("INSERT INTO payments (user_id, txn_id, product, quantity, amount, status) VALUES (?,?,?,?,?,?)", (uid, txn_id, product, quantity, amount, 'pending'))
        conn.commit()
        flash('Payment submitted for admin verification','info')
    except Exception as e:
        flash('Transaction ID duplicate or error','danger')
    conn.close()
    return redirect('/wallet')

# Admin payments (approve / reject)
@app.route('/admin/payments')
def admin_payments():
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com':
        return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT p.id, u.email, p.txn_id, p.product, p.quantity, p.amount, p.status, p.created_at FROM payments p JOIN users u ON p.user_id=u.id ORDER BY p.created_at DESC")
    rows = c.fetchall(); conn.close()
    return render_template('admin_payments.html', payments=rows)

@app.route('/admin/payments/approve/<int:pid>')
def admin_payments_approve(pid):
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com':
        return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT user_id, txn_id, product, quantity, amount FROM payments WHERE id=?", (pid,))
    p = c.fetchone()
    if not p:
        flash('Payment not found','danger'); conn.close(); return redirect('/admin/payments')
    user_id, txn_id, product, quantity, amount = p
    if product == 'vip':
        amt_map = {50:3, 100:7, 250:15, 500:30}
        days = amt_map.get(int(amount), 3)
        c.execute("SELECT vip_until FROM users WHERE id=?", (user_id,))
        cur = c.fetchone()[0]
        try:
            cur_dt = datetime.strptime(cur, '%Y-%m-%d') if cur else datetime.now()
        except:
            cur_dt = datetime.now()
        new_expiry = max(datetime.now(), cur_dt) + timedelta(days=days)
        c.execute("UPDATE users SET vip_until=? WHERE id=?", (new_expiry.strftime('%Y-%m-%d'), user_id))
        c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (user_id, 'VIP Purchase', 0, f'Admin approved txn {pid}'))
    elif product == 'diamond':
        map_amt = {50:10, 70:20, 100:50, 150:100, 300:500, 500:1000}
        diamonds = map_amt.get(int(amount), 0)
        if diamonds:
            c.execute("UPDATE users SET diamonds = diamonds + ? WHERE id=?", (diamonds, user_id))
            c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (user_id, 'Diamond Purchase', diamonds, f'Admin approved txn {pid}'))
    elif product == 'wallet':
        c.execute("UPDATE users SET wallet = wallet + ? WHERE id=?", (amount, user_id))
        c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (user_id, 'Wallet Topup', amount, f'Admin approved txn {pid}'))
    c.execute("UPDATE payments SET status='approved' WHERE id=?", (pid,))
    conn.commit(); conn.close()
    flash('Payment approved','success')
    return redirect('/admin/payments')

@app.route('/admin/payments/reject/<int:pid>')
def admin_payments_reject(pid):
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com':
        return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("UPDATE payments SET status='rejected' WHERE id=?", (pid,))
    conn.commit(); conn.close()
    flash('Payment rejected','info')
    return redirect('/admin/payments')

# Buy services
@app.route('/buy_service', methods=['GET','POST'])
def buy_service():
    if 'user' not in session:
        return redirect('/login')
    auto_update_orders()
    email = session['user']
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=?", (email,))
    user = c.fetchone(); conn.close()
    services = PRICE_TABLE
    pre_service = request.args.get('service','')
    pre_package = request.args.get('package','')
    pre_cost = request.args.get('cost','')
    if request.method == 'POST':
        service_key = request.form['service']
        quantity = int(request.form['quantity'])
        method = request.form['method']  # diamonds/gold/wallet
        target_link = request.form['target_link']
        is_admin = (email == 'guccieditz1@gmail.com')
        costs = compute_cost(service_key, quantity)
        if not costs:
            flash('Invalid service','danger')
            return redirect('/buy_service')
        if method == 'diamonds':
            cost = costs['diamonds']
            if not is_admin and user[4] < cost:
                flash('Not enough Diamonds','danger'); return redirect('/buy_service')
        elif method == 'gold':
            cost = costs['gold']
            if not is_admin and user[3] < cost:
                flash('Not enough Gold','danger'); return redirect('/buy_service')
        else:
            cost = costs['rupees']
            if not is_admin and user[5] < cost:
                flash('Not enough Wallet Balance','danger'); return redirect('/buy_service')
        conn = sqlite3.connect(DB_FILE); c = conn.cursor()
        # Deduct and transaction log for non-admin
        c.execute("SELECT id FROM users WHERE email=?", (email,))
        uid = c.fetchone()[0]
        if not is_admin:
            if method == 'diamonds':
                c.execute("UPDATE users SET diamonds = diamonds - ? WHERE email=?", (cost, email))
                c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (uid, 'Spend Diamonds', cost, f'Bought {quantity} of {service_key}'))
            elif method == 'gold':
                c.execute("UPDATE users SET coins = coins - ? WHERE email=?", (cost, email))
                c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (uid, 'Spend Gold', cost, f'Bought {quantity} of {service_key}'))
            else:
                c.execute("UPDATE users SET wallet = wallet - ? WHERE email=?", (cost, email))
                c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (uid, 'Spend Wallet', cost, f'Bought {quantity} of {service_key}'))
        label = PRICE_TABLE[service_key]['label']
        c.execute("INSERT INTO orders (user_email, service_key, service_label, option_type, quantity, cost, currency, target_link, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (email, service_key, label, 'standard', quantity, cost, method, target_link, 'Processing'))
        conn.commit(); conn.close()
        flash('Order placed and pending delivery','success')
        return redirect('/orders')
    return render_template('buy_service.html', services=services, pre_service=pre_service, pre_package=pre_package, pre_cost=pre_cost, user=user)

@app.route('/orders')
def orders_view():
    if 'user' not in session:
        return redirect('/login')
    auto_update_orders()
    email = session['user']
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT id, service_label, option_type, quantity, cost, currency, target_link, status, created_at FROM orders WHERE user_email=? ORDER BY created_at DESC", (email,))
    rows = c.fetchall(); conn.close()
    return render_template('orders.html', orders=rows)

# Admin order management
@app.route('/admin/orders')
def admin_orders():
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com':
        return redirect('/login')
    auto_update_orders()
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT id, user_email, service_label, option_type, quantity, cost, currency, target_link, status, created_at FROM orders ORDER BY created_at DESC")
    rows = c.fetchall(); conn.close()
    return render_template('admin_orders.html', orders=rows)

@app.route('/admin/orders/approve/<int:oid>')
def admin_orders_approve(oid):
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com':
        return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT user_email, service_key, quantity, currency, cost FROM orders WHERE id=?", (oid,))
    o = c.fetchone()
    if not o:
        conn.close(); flash('Order not found','danger'); return redirect('/admin/orders')
    email, skey, qty, currency, cost = o
    apply_service_to_user(email, skey, qty)
    c.execute("UPDATE orders SET status='Completed' WHERE id=?", (oid,))
    c.execute("INSERT INTO notifications (user_email, message) VALUES (?,?)", (email, f"Your order #{oid} has been completed by admin." ))
    c.execute("SELECT id FROM users WHERE email=?", (email,))
    uid = c.fetchone()[0]
    c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (uid, 'Order Completed (Admin)', 0, f'Order #{oid} completed by admin'))
    conn.commit(); conn.close()
    flash('Order approved and delivered','success')
    return redirect('/admin/orders')

@app.route('/admin/orders/reject/<int:oid>')
def admin_orders_reject(oid):
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com':
        return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT user_email, cost, currency FROM orders WHERE id=?", (oid,))
    o = c.fetchone()
    if not o:
        conn.close(); flash('Order not found','danger'); return redirect('/admin/orders')
    email, cost, currency = o
    if currency == 'diamonds':
        c.execute("UPDATE users SET diamonds = diamonds + ? WHERE email=?", (cost, email))
    elif currency == 'gold':
        c.execute("UPDATE users SET coins = coins + ? WHERE email=?", (cost, email))
    else:
        c.execute("UPDATE users SET wallet = wallet + ? WHERE email=?", (cost, email))
    c.execute("UPDATE orders SET status='Rejected' WHERE id=?", (oid,))
    c.execute("SELECT id FROM users WHERE email=?", (email,))
    uid = c.fetchone()[0]
    c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (uid, 'Order Rejected / Refund', cost, f'Order #{oid} refunded'))
    conn.commit(); conn.close()
    flash('Order rejected and refunded','info')
    return redirect('/admin/orders')

# Ads & rewards
@app.route('/watch_ads', methods=['GET'])
def watch_ads():
    if 'user' not in session:
        return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT ads_watched FROM users WHERE email=?", (session['user'],))
    aw = c.fetchone()[0]; conn.close()
    return render_template('watch_ads.html', ads_watched=aw)

@app.route('/ads_click', methods=['POST'])
def ads_click():
    if 'user' not in session:
        return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("UPDATE users SET ads_watched = ads_watched + 1 WHERE email=?", (session['user'],))
    c.execute("SELECT id FROM users WHERE email=?", (session['user'],))
    uid = c.fetchone()[0]
    c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (uid, 'Ad Watched', 0, 'Watched ad reward progress'))
    conn.commit(); conn.close()
    flash('Thanks for watching the ad. Progress updated.','success')
    return redirect('/rewards')

@app.route('/rewards')
def rewards():
    if 'user' not in session: return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT ads_watched FROM users WHERE email=?", (session['user'],))
    aw = c.fetchone()[0]; conn.close()
    rewards_def = [
        {'type':'Followers','ads_required':10,'reward':50},
        {'type':'Likes','ads_required':5,'reward':20},
        {'type':'Views','ads_required':3,'reward':10},
        {'type':'Subscribers','ads_required':15,'reward':100},
    ]
    for r in rewards_def: r['unlocked'] = aw >= r['ads_required']
    return render_template('rewards.html', ads_watched=aw, rewards=rewards_def)

@app.route('/claim_reward/<reward_type>', methods=['POST'])
def claim_reward(reward_type):
    if 'user' not in session: return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT id, ads_watched, coins FROM users WHERE email=?", (session['user'],))
    u = c.fetchone(); user_id, ads_watched, coins = u
    rewards_map = {
        'Followers': {'ads_required':10,'reward':50},
        'Likes': {'ads_required':5,'reward':20},
        'Views': {'ads_required':3,'reward':10},
        'Subscribers': {'ads_required':15,'reward':100},
    }
    if reward_type not in rewards_map:
        conn.close(); flash('Invalid reward','danger'); return redirect('/rewards')
    r = rewards_map[reward_type]
    if ads_watched < r['ads_required']:
        conn.close(); flash('Not enough ads watched','danger'); return redirect('/rewards')
    new_ads = ads_watched - r['ads_required']; new_coins = coins + r['reward']
    c.execute("UPDATE users SET ads_watched=?, coins=? WHERE id=?", (new_ads, new_coins, user_id))
    c.execute("INSERT INTO claims (user_id, reward_type, reward_value) VALUES (?,?,?)", (user_id, reward_type, r['reward']))
    c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (user_id, 'Claim Reward', r['reward'], f'Claimed {reward_type} reward'))
    conn.commit(); conn.close()
    flash('Reward claimed successfully','success')
    return redirect('/claim_history')

@app.route('/claim_history')
def claim_history():
    if 'user' not in session: return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email=?", (session['user'],))
    uid = c.fetchone()[0]
    c.execute("SELECT reward_type, reward_value, created_at FROM claims WHERE user_id=? ORDER BY created_at DESC", (uid,))
    rows = c.fetchall(); conn.close()
    return render_template('claim_history.html', history=rows)

# Support chat (VIP/diamond only)
@app.route('/support_chat', methods=['GET','POST'])
def support_chat():
    if 'user' not in session: return redirect('/login')
    email = session['user']
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT vip_until, diamonds FROM users WHERE email=?", (email,))
    u = c.fetchone(); vip_until = u[0]; diamonds = u[1]
    vip_active = False
    try: vip_active = bool(vip_until and datetime.strptime(vip_until, '%Y-%m-%d') >= datetime.now())
    except: vip_active = False
    if not vip_active and diamonds < 1:
        conn.close(); return render_template('support_chat.html', vip=False, messages=[])
    if request.method == 'POST':
        msg = request.form['message']
        c.execute("INSERT INTO support_chat (user_email, message) VALUES (?,?)", (email, msg))
        conn.commit()
    c.execute("SELECT id, message, date FROM support_chat WHERE user_email=? ORDER BY date DESC", (email,))
    msgs = c.fetchall(); conn.close()
    return render_template('support_chat.html', vip=True, messages=msgs)

# Notifications
@app.route('/notifications')
def notifications():
    if 'user' not in session: return redirect('/login')
    email = session['user']
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT id, message, created_at FROM notifications WHERE user_email=? AND seen=0 ORDER BY id DESC", (email,))
    notifs = c.fetchall()
    c.execute("UPDATE notifications SET seen=1 WHERE user_email=?", (email,))
    conn.commit(); conn.close()
    return render_template('notifications.html', notifs=notifs)

# User transactions view
@app.route('/transactions')
def transactions_view():
    if 'user' not in session: return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email=?", (session['user'],))
    uid = c.fetchone()[0]
    c.execute("SELECT type, amount, details, date FROM transactions WHERE user_id=? ORDER BY date DESC", (uid,))
    rows = c.fetchall(); conn.close()
    return render_template('transactions.html', records=rows)

# Admin pages
@app.route('/admin')
def admin_dashboard():
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com': return redirect('/login')
    return render_template('admin_dashboard.html')

@app.route('/admin/users')
def admin_users():
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com': return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT id, email, coins, vip_until, diamonds FROM users")
    rows = c.fetchall(); conn.close()
    return render_template('admin_users.html', users=rows)

@app.route('/admin/wallets')
def admin_wallets():
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com': return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT id, email, coins, diamonds, wallet FROM users")
    rows = c.fetchall(); conn.close()
    return render_template('admin_wallets.html', wallets=rows)

@app.route('/admin/ads', methods=['GET','POST'])
def admin_ads():
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com': return redirect('/login')
    ads_file = 'ads.html'
    if request.method=='POST':
        code = request.form['ad_code']
        with open(ads_file,'w',encoding='utf-8') as f: f.write(code)
        flash('Ad saved','success')
    content = ''
    if os.path.exists(ads_file):
        with open(ads_file,'r',encoding='utf-8') as f: content = f.read()
    return render_template('admin_ads.html', ad_content=content)

@app.route('/admin/settings', methods=['GET','POST'])
def admin_settings():
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com': return redirect('/login')
    settings_file = 'settings.txt'
    if request.method == 'POST':
        s = request.form['settings']
        with open(settings_file,'w',encoding='utf-8') as f: f.write(s)
        flash('Settings saved','success')
    content = ''
    if os.path.exists(settings_file):
        with open(settings_file,'r',encoding='utf-8') as f: content = f.read()
    return render_template('admin_settings.html', settings=content)

@app.route('/admin/add_funds', methods=['GET','POST'])
def admin_add_funds():
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com': return redirect('/login')
    message = ''
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    if request.method == 'POST':
        user_id = int(request.form['user_id']); fund_type = request.form['fund_type']; amount = float(request.form['amount'])
        if fund_type=='gold':
            c.execute("UPDATE users SET coins = coins + ? WHERE id=?", (amount, user_id))
            c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (user_id, 'Admin Add Gold', amount, 'Admin credited gold'))
        else:
            c.execute("UPDATE users SET diamonds = diamonds + ? WHERE id=?", (amount, user_id))
            c.execute("INSERT INTO transactions (user_id, type, amount, details) VALUES (?,?,?,?)", (user_id, 'Admin Add Diamond', amount, 'Admin credited diamonds'))
        conn.commit(); message = 'Funds added'
    c.execute("SELECT id, email FROM users"); users = c.fetchall(); conn.close()
    return render_template('admin_add_funds.html', users=users, message=message)

@app.route('/admin/transactions')
def admin_transactions_all():
    if 'user' not in session or session['user'] != 'guccieditz1@gmail.com': return redirect('/login')
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT t.id, u.email, t.type, t.amount, t.details, t.date FROM transactions t JOIN users u ON t.user_id=u.id ORDER BY t.date DESC")
    rows = c.fetchall(); conn.close()
    return render_template('admin_transactions.html', records=rows)

if __name__ == '__main__':
    # Local dev server
    app.run(host='0.0.0.0', port=5000, debug=True)