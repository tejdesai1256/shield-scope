import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")

if not MONGODB_URI:
    raise ValueError("MONGODB_URI is not configured")

client = MongoClient(MONGODB_URI)

db = client["website_security_scanner"]

users_collection = db["users"]
scans_collection = db["scans"]
scheduled_scans_collection = db["scheduled_scans"]

try:
    client.admin.command("ping")
    print("MongoDB Atlas connected successfully!")
    users_collection.create_index("email", unique=True)
    scans_collection.create_index([("userId", 1), ("createdAt", -1)])
    scheduled_scans_collection.create_index([("userId", 1)], unique=True)
except Exception as e:
    print("MongoDB connection failed:", e)
