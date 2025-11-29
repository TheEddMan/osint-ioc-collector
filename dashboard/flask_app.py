from flask import Flask, render_template_string, jsonify, request
from database.db import get_recent_iocs
import sqlite3

app = Flask(__name__)

# ---- helper for counts per day ----

def get_counts_per_day(limit_days: int = 7):
    conn = sqlite3.connect("osint.db")
    cur = conn.cursor()
    cur.execute("""
        SELECT DATE(first_seen), type, COUNT(*)
        FROM iocs
        WHERE first_seen >= datetime('now', ?)
        GROUP BY DATE(first_seen), type
        ORDER BY DATE(first_seen)
    """, (f"-{limit_days} days",))
    rows = cur.fetchall()
    conn.close()

    # structure: {date: {type: count}}
    data = {}
    for day, t, c in rows:
        data.setdefault(day, {})[t] = c
    return data


TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>OSINT Harvester Dashboard</title>
    <meta http-equiv="refresh" content="60">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ccc; padding: 6px; font-size: 13px; }
        th { background: #eee; }
        h1 { margin-bottom: 5px; }
        .ts { font-size: 12px; color: #555; }
        #searchBox { padding: 6px; width: 250px; margin-top: 10px; }
        #chart-container { width: 100%; max-width: 800px; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>OSINT Harvester - Recent IOCs</h1>
    <p class="ts">Auto-refresh every 60s. Showing latest {{ rows|length }} IOCs.</p>

    <div id="chart-container">
        <canvas id="iocChart"></canvas>
    </div>

    <input id="searchBox" type="text" placeholder="Search value or source...">

    <table id="iocTable">
        <thead>
        <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Value</th>
            <th>Source</th>
            <th>First Seen</th>
        </tr>
        </thead>
        <tbody>
        {% for row in rows %}
        <tr>
            <td>{{ row[0] }}</td>
            <td>{{ row[1] }}</td>
            <td>{{ row[2] }}</td>
            <td>{{ row[3] }}</td>
            <td>{{ row[5] }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>

<script>
// client-side search
const searchBox = document.getElementById('searchBox');
searchBox.addEventListener('keyup', function() {
    const filter = this.value.toLowerCase();
    const rows = document.querySelectorAll('#iocTable tbody tr');
    rows.forEach(r => {
        const text = r.innerText.toLowerCase();
        r.style.display = text.includes(filter) ? '' : 'none';
    });
});

// chart
fetch('/api/ioc_counts')
  .then(r => r.json())
  .then(data => {
    const labels = data.labels;
    const types = data.types;
    const datasets = types.map((t, idx) => ({
        label: t,
        data: data.series[t],
        fill: false,
        tension: 0.1
    }));

    const ctx = document.getElementById('iocChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: { labels, datasets },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom' },
                title: { display: true, text: 'IOC count per day (last 7 days)' }
            }
        }
    });
  });
</script>

</body>
</html>
"""


@app.route("/")
def index():
    rows = get_recent_iocs(limit=300)
    return render_template_string(TEMPLATE, rows=rows)


@app.route("/api/ioc_counts")
def api_ioc_counts():
    data = get_counts_per_day(limit_days=7)
    labels = sorted(data.keys())
    all_types = set()
    for d in data.values():
        all_types.update(d.keys())
    types = sorted(all_types)

    series = {t: [] for t in types}
    for day in labels:
        day_data = data.get(day, {})
        for t in types:
            series[t].append(day_data.get(t, 0))

    return jsonify({"labels": labels, "types": types, "series": series})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
