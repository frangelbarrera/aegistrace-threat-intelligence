# main.py
from collectors import fetch_all_sources
from nlp_processor import process_nlp
from predictor import predict_trends
from ioc_extractor import extract_iocs
from enricher import enrich_iocs
from dashboard_generator import generate_dashboard
from storage import init_db, save_threats, save_iocs
import pandas as pd

print("🚀 Starting AegisTrace...")

# 0. Initialize the database
init_db()

# 1. Collect threat data from all configured sources
threats = fetch_all_sources()

# 2. Process threats with NLP (entity extraction, classification, summaries)
threats = process_nlp(threats)

# 3. Save processed threats into the database
save_threats(threats)

# 4. Predict threat trends (7-day forecast)
predictions = predict_trends(threats)

# 5. Extract Indicators of Compromise (IoCs) from the collected threats
iocs = extract_iocs(threats)

# 6. Enrich IoCs with external intelligence sources (if enabled and available)
iocs_enriched = enrich_iocs(iocs)

# 7. Save enriched IoCs into the database
save_iocs(iocs_enriched)

# 8. Export enriched IoCs to CSV for external analysis
pd.DataFrame(iocs_enriched).to_csv("iocs_enriched.csv", index=False)
print("[+] IoCs exported to iocs_enriched.csv")

# 9. Generate the interactive HTML dashboard
generate_dashboard(threats, predictions, iocs_enriched=iocs_enriched)

print("✅ Done! Open dashboard.html to view results.")

