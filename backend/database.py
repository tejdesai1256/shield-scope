import os
import re
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
    scans_collection.create_index("category")
    scheduled_scans_collection.create_index([("userId", 1)], unique=True)
except Exception as e:
    print("MongoDB connection failed:", e)


def get_scans_by_category(category: str, user_id: str = None):
    """
    Query scans by category and user_id from MongoDB Atlas.
    """
    query = {}
    
    # Category filter
    if category and category.lower() != "all":
        query["category"] = {"$regex": f"^{re.escape(category)}$", "$options": "i"}

    # User filter (matching both userId and user_id for compatibility)
    if user_id is not None:
        user_id_conditions = [
            {"userId": user_id},
            {"user_id": user_id}
        ]
        # Handle int/str representations
        try:
            if isinstance(user_id, str) and user_id.isdigit():
                user_id_conditions.append({"userId": int(user_id)})
                user_id_conditions.append({"user_id": int(user_id)})
            elif isinstance(user_id, int):
                user_id_conditions.append({"userId": str(user_id)})
                user_id_conditions.append({"user_id": str(user_id)})
        except Exception:
            pass

        if "category" in query:
            query = {
                "category": query["category"],
                "$or": user_id_conditions
            }
        else:
            query = {"$or": user_id_conditions}

    return list(scans_collection.find(query).sort("createdAt", -1).limit(100))


