from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('/app/data/security_feeds.db')
    conn.row_factory = sqlite3.Row
    return conn

# Homepage with top feeds and source list
@app.route('/')
def index():
    conn = get_db_connection()
    c = conn.cursor()

    # Full list of sources (unchanged)
    sources = [
        "SecurityWeek", "The Hacker News", "BleepingComputer", "Sophos Research", "Microsoft Security", 
        "Red Hat Security", "Dark Reading", "Krebs on Security", "CISA Alerts", "ZDI Upcoming", 
        "ZDI Published", "In the Wild Exploits", "Ubuntu Security", "Center for Internet Security", 
        "Universal Cyberalerts.io Security Alerts"
    ]

    # Fetch top 5 feeds for key sources
    top_sources = ["The Hacker News", "BleepingComputer", "SecurityWeek"]
    top_feeds = {}
    for source in top_sources:
        c.execute(
            "SELECT title, link, pub_date, source, category, description FROM feeds WHERE source = ? ORDER BY pub_date DESC LIMIT 5",
            (source,)
        )
        top_feeds[source] = [dict(row) for row in c.fetchall()]

    conn.close()
    return render_template('index.html', sources=sources, top_feeds=top_feeds)

# Dynamic route for each source (unchanged)
@app.route('/<source>')
def source_page(source):
    conn = get_db_connection()
    source = source.replace('_', ' ')
    feeds = conn.execute(
        "SELECT title, link, pub_date, source, category, description FROM feeds WHERE source = ? ORDER BY pub_date DESC LIMIT 50",
        (source,)
    ).fetchall()
    conn.close()
    if not feeds:
        return f"No recent feeds found for {source}", 404
    return render_template('source.html', feeds=feeds, source=source)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)
