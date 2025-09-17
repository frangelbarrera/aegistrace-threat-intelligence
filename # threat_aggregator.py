# threat_aggregator.py
# Threat Intelligence Aggregator for VS Code - Hackathon MVP (Sep 13, 2025, 02:04 PM IST)
# Generates README.md, dashboard.html, and threat_aggregator.zip locally

import os
import requests
import xml.etree.ElementTree as ET
import spacy
import pandas as pd
from datetime import datetime, timedelta
from statsmodels.tsa.arima.model import ARIMA
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import zipfile
import warnings
warnings.filterwarnings('ignore')

# Config (Update OTX_API_KEY with your key from https://otx.alienvault.com/api-keys)
OTX_API_KEY = 'your_otx_key_here'  # Replace with your key or set via os.environ['OTX_API_KEY'] = 'your_key'
RSS_FEED_URL = 'https://krebsonsecurity.com/feed/'
X_QUERY = 'cyber threat OR ransomware filter:news since:2025-09-01'

# Load spaCy
try:
    nlp = spacy.load('en_core_web_sm')
except OSError:
    print("Error: Run 'python -m spacy download en_core_web_sm' first!")
    exit(1)

# Step 1: Fetch Threat Data
def fetch_data():
    threats = []
    
    # OTX Pulses
    if OTX_API_KEY != 'your_otx_key_here':
        otx_url = f'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10'
        headers = {'X-OTX-API-KEY': OTX_API_KEY}
        for attempt in range(3):
            try:
                resp = requests.get(otx_url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    pulses = resp.json().get('results', [])
                    for pulse in pulses:
                        threats.append({
                            'title': pulse.get('name', 'Unknown Threat'),
                            'summary': pulse.get('description', '')[:200] + '...',
                            'url': pulse.get('short_url', '#'),
                            'sector': pulse.get('industries', ['General'])[0],
                            'timestamp': datetime.fromisoformat(pulse.get('created', datetime.now().isoformat()))
                        })
                    break
                else:
                    print(f"OTX Error: Status {resp.status_code}")
            except Exception as e:
                print(f"OTX attempt {attempt+1} failed: {e}")
    else:
        print("OTX API key missing. Using mocks.")
    
    # RSS via requests + XML
    try:
        resp = requests.get(RSS_FEED_URL, timeout=10)
        if resp.status_code == 200:
            root = ET.fromstring(resp.content)
            entries = root.findall('.//item')
            for entry in entries[:5]:
                title = entry.find('title').text if entry.find('title') is not None else 'Unknown'
                link = entry.find('link').text if entry.find('link') is not None else '#'
                summary = entry.find('description').text[:200] + '...' if entry.find('description') is not None else ''
                threats.append({
                    'title': title,
                    'summary': summary,
                    'url': link,
                    'sector': 'General',
                    'timestamp': datetime.now() - timedelta(hours=1)
                })
    except Exception as e:
        print(f"RSS fetch failed: {e}")
    
    # Mock X Posts (reflecting 2025 trends)
    mock_x = [
        {'title': 'AI Phishing Surge #CyberSec', 'summary': 'LockBit uses deepfake voices to target banks in USA.', 'url': 'https://x.com/mock1', 'sector': 'Finance', 'timestamp': datetime.now()},
        {'title': 'IoT Zero-Day Alert', 'summary': 'APT28 exploits smart cameras in Europe.', 'url': 'https://x.com/mock2', 'sector': 'IoT', 'timestamp': datetime.now() - timedelta(minutes=30)},
        {'title': 'Ransomware Hits Healthcare', 'summary': '25% attack spike reported.', 'url': 'https://x.com/mock3', 'sector': 'Healthcare', 'timestamp': datetime.now() - timedelta(hours=2)}
    ]
    threats.extend(mock_x)
    
    return threats[:15]

# Step 2: NLP Processing
def process_nlp(threats):
    for threat in threats:
        doc = nlp(threat['summary'])
        entities = [ent.text for ent in doc.ents if ent.label_ in ['ORG', 'GPE', 'MONEY', 'NORP']]
        threat['entities'] = list(set(entities))[:5]
        threat['summary_nlp'] = ' '.join([sent.text.strip() for sent in doc.sents][:2])
    return threats

# Step 3: Trend Prediction
def predict_trends(threats, days_ahead=7):
    dates = pd.date_range(end=datetime.now(), periods=30)
    mock_counts = pd.Series([4 + i*0.3 + (i%5)*2 for i in range(30)], index=dates)
    try:
        model = ARIMA(mock_counts, order=(1,1,1))
        model_fit = model.fit()
        forecast = model_fit.forecast(steps=days_ahead)
        forecast_dates = pd.date_range(start=datetime.now() + timedelta(days=1), periods=days_ahead)
        pred_df = pd.DataFrame({'date': forecast_dates, 'predicted_threats': forecast.values})
        pred_df['risk_level'] = pd.cut(pred_df['predicted_threats'], bins=[0, 5, 10, float('inf')], labels=['Low', 'Medium', 'High'])
    except Exception as e:
        print(f"ARIMA failed: {e}. Using mock predictions.")
        pred_df = pd.DataFrame({
            'date': forecast_dates,
            'predicted_threats': [18 + i*-0.1 for i in range(days_ahead)],  # Matches chart trend
            'risk_level': ['High']*days_ahead if 18 > 10 else ['Medium']*days_ahead
        })
    return pred_df

# Step 4: Visualize and Save
def display_dashboard(threats, predictions):
    df_threats = pd.DataFrame(threats)
    sector_counts = df_threats.groupby('sector').size().reset_index(name='count')
    fig1 = px.bar(sector_counts, x='sector', y='count', title='Threats by Sector', color='sector')
    
    fig2 = px.line(predictions, x='date', y='predicted_threats', color='risk_level', title='7-Day Threat Forecast')
    
    fig = make_subplots(rows=2, cols=1, subplot_titles=('Threats by Sector', '7-Day Forecast'))
    fig.add_trace(fig1.data[0], row=1, col=1)
    fig.add_trace(fig2.data[0], row=2, col=1)
    fig.update_layout(height=600, title_text="Threat Intelligence Aggregator")
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Threat Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script></head>
    <body>
    <h1>Threat Intelligence Aggregator Dashboard</h1>
    {fig.to_html(full_html=False, include_plotlyjs='cdn')}
    <h2>Recent Threats</h2>
    {df_threats[['title', 'summary_nlp', 'entities', 'sector']].head(10).to_html(index=False)}
    <p>Total Threats: {len(threats)} | Top Sector: {df_threats['sector'].mode().iloc[0] if not df_threats.empty else 'N/A'}</p>
    </body>
    </html>
    """
    with open('dashboard.html', 'w') as f:
        f.write(html_content)
    print("Dashboard saved as dashboard.html in the current directory.")

    readme_content = """# Threat Intelligence Aggregator
Hackathon project (Sep 13, 2025)
## Overview
Aggregates cyber threat data from OTX, RSS (Krebs), and X posts. Uses spaCy for NLP, ARIMA for predictions, and Plotly for visualization.
## Setup
1. Install: `pip install requests spacy plotly pandas statsmodels`
2. Install spaCy model: `python -m spacy download en_core_web_sm`
3. Set OTX_API_KEY in code or env.
4. Run: `python threat_aggregator.py`
## Outputs
- Console: Threat summaries, entities, predictions
- dashboard.html: Interactive charts + table
## Team
[Your Names] | GitHub: [your-repo]
"""
    with open('README.md', 'w') as f:
        f.write(readme_content)
    print("README.md saved in the current directory.")

    with open('threat_aggregator.py', 'w') as f:
        f.write(open(__file__).read())
    print("threat_aggregator.py saved in the current directory.")

    with zipfile.ZipFile('threat_aggregator.zip', 'w', zipfile.ZIP_DEFLATED) as z:
        z.write('threat_aggregator.py')
        z.write('README.md')
        z.write('dashboard.html')
    print("Zip created: threat_aggregator.zip")

# Main
print(f"Starting Threat Aggregator in VS Code (02:04 PM IST, Sep 13, 2025)...")
threats = fetch_data()
print(f"\nFetched {len(threats)} threats.")
threats = process_nlp(threats)

print("\nTop Entities:")
all_entities = [ent for t in threats for ent in t['entities']]
print(list(set(all_entities))[:10])

predictions = predict_trends(threats)
print("\nPredictions (First 3 Days):")
for _, row in predictions.head(3).iterrows():
    print(f"{row['date'].strftime('%Y-%m-%d')}: {row['predicted_threats']:.1f} threats ({row['risk_level']} risk)")

display_dashboard(threats, predictions)
print("\nDone! Check files and open dashboard.html in a browser.")