import firebase_admin
from firebase_admin import credentials, firestore

# Initialize Firebase (only once)
cred = credentials.Certificate(r"C:\Users\anamika2876\Downloads\SecureCloud_Project\firebase_key.json")
firebase_admin.initialize_app(cred)

db = firestore.client()

# Add user
def add_user(username, password):
    db.collection("users").document(username).set({
        "password": password
    })

# Get user
def get_user(username):
    doc = db.collection("users").document(username).get()
    if doc.exists:
        return doc.to_dict()["password"]
    return None

# Add log
def add_log(entry):
    db.collection("logs").add({
        "entry": entry
    })

# Get logs
def get_logs():
    logs = db.collection("logs").stream()
    return [log.to_dict()["entry"] for log in logs]