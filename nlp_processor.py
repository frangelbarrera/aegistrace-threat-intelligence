# nlp_processor.py
import spacy
from config import THREAT_CATEGORIES

# === Load spaCy model ===
# Attempt to load the English language model.
# If missing, instruct the user to download it and exit.
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("[!] spaCy model missing. Run: python -m spacy download en_core_web_sm")
    exit(1)

def classify_threat(text):
    """
    Classify a threat into a category based on keyword matching.

    Args:
        text (str): The text to classify (title + summary).

    Returns:
        str: The category name if a keyword match is found, otherwise "Uncategorized".
    """
    text_lower = text.lower()
    for category, keywords in THREAT_CATEGORIES.items():
        if any(keyword in text_lower for keyword in keywords):
            return category
    return "Uncategorized"

def process_nlp(threats):
    """
    Process a list of threat records using NLP:
      - Extract named entities (ORG, GPE, MONEY, NORP)
      - Generate a short NLP-based summary (first 2 sentences)
      - Classify the threat type based on title and summary

    Args:
        threats (list of dict): Threat records containing at least 'summary' and 'title'.

    Returns:
        list of dict: Updated threat records with:
            - entities: list of extracted named entities (max 5)
            - summary_nlp: short summary generated from the first 2 sentences
            - threat_type: classification label
    """
    for threat in threats:
        # Process the summary text with spaCy
        doc = nlp(threat["summary"])

        # Extract relevant named entities
        entities = [ent.text for ent in doc.ents if ent.label_ in ["ORG", "GPE", "MONEY", "NORP"]]
        threat["entities"] = list(set(entities))[:5]

        # Generate a short summary from the first two sentences
        threat["summary_nlp"] = " ".join([sent.text.strip() for sent in doc.sents][:2])

        # Classify the threat type based on title + summary
        threat["threat_type"] = classify_threat(threat["title"] + " " + threat["summary"])

    return threats

