# SecurityNewsCast
securitynewscast/
├── data/
│   └── security_feeds.db
├── docker-compose.yml
├── web/
│   └── app.py
└── worker/
    ├── worker.py
    └── Dockerfile

SecurityNewsCast Dashboard

Welcome to Security News Feed Dashboard, a lightweight, Dockerized Flask application that aggregates and displays the latest cybersecurity news and advisories from top sources in a clean, user-friendly interface. Built with Python, SQLite, and Bootstrap, this project pulls real-time feeds from leading security outlets, offering a centralized hub for staying informed about vulnerabilities, exploits, and alerts. Whether you’re a security professional or enthusiast, this tool delivers actionable insights at a glance.

Features
-Dynamic Dashboard: The homepage showcases the top 5 recent articles from "The Hacker News," "BleepingComputer," and "SecurityWeek," grouped in sleek cards for instant visibility.
-Source Sidebar: A fixed left panel lists all supported sources, linking to detailed views of up to 50 articles per source.
-Detailed Source Pages: Dive into individual feeds with tables displaying title, category, description, and date, refreshed every 5 minutes.
-Broad Coverage: Aggregates 15+ sources, including SecurityWeek, The Hacker News, BleepingComputer, CISA Alerts, Krebs on Security, and more.
-SQLite Backend: Stores feed data in a lightweight database, updated periodically by a background worker.
-Dockerized: Easy deployment with Docker Compose, including Flask web server and feed fetcher.
-Responsive Design: Built with Bootstrap 5 and the Inter font for a modern, mobile-friendly UI.

Supported Sources

Vulnerabilities: SecurityWeek, ZDI Upcoming, ZDI Published, Dark Reading, NIST NVD, Red Hat Security, Ubuntu Security

Exploits: In the Wild Exploits, The Hacker News, BleepingComputer, Krebs on Security

Advisories: CISA Alerts, Sophos Research, Microsoft Security, Center for Internet Security, Universal Cyberalerts.io Security Alerts

Screenshot
![image](https://github.com/user-attachments/assets/84f5095a-23a6-4346-902a-46672c06eed3)


Getting Started
-Prerequisites
-Docker and Docker Compose installed
-Basic familiarity with command-line tools
-Installation

Clone the Repository:


Collapse

Wrap

Copy
git clone https://github.com/kendalllewis/SecurityNewsCast.git

cd securitynewscast

Build and Run:

docker-compose up --build -d

This starts the Flask web server (web) and feed fetcher (worker) services.
Data is stored in a persistent SQLite database at ./data/security_feeds.db.

Access the Dashboard:
Open your browser to http://localhost:5000 (or https://localhost:5000 if configured with SSL).

The homepage loads with top feeds and a source sidebar.

Configuration
Feed Interval: Adjust the fetch interval by setting the FETCH_INTERVAL environment variable in docker-compose.yml (default: 300 seconds).
Custom Sources: Modify worker.py’s sources dictionary to add or remove feeds.

Usage
Homepage: View the latest from top sources instantly. Click article titles to visit the original posts.
Source Pages: Click any source in the sidebar (e.g., /The_Hacker_News) for a detailed table of recent articles, including descriptions where available.
Updates: The worker refreshes feeds every 5 minutes, pruning entries older than 20 days.

Project Structure
app.py: Flask application serving the web interface.
worker.py: Background script fetching and storing feeds in SQLite.
templates/index.html: Homepage with top feeds and source sidebar.
templates/source.html: Detailed source view with article tables.
docker-compose.yml: Docker configuration for web and worker services.
data/: Volume for persistent SQLite storage (security_feeds.db).

Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss your ideas. Potential enhancements:

Add more feed sources or categories.
Enhance the UI with charts or filters.
Improve error handling or logging.

License
This project is licensed under the MIT License—see the LICENSE file for details.

Acknowledgments
Built with Flask, Feedparser, and Bootstrap.
Inspired by the need for a simple, self-hosted security news aggregator.
