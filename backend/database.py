import os
import dns.resolver
from pymongo import MongoClient
from dotenv import load_dotenv

# Ensure dnspython uses reliable public DNS nameservers for MongoDB Atlas SRV resolution
try:
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
    dns.resolver.default_resolver.timeout = 5.0
    dns.resolver.default_resolver.lifetime = 10.0
except Exception:
    pass

env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(dotenv_path=env_path)
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")

if not MONGODB_URI:
    raise ValueError("MONGODB_URI is not configured")

client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)

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

