from dotenv import load_dotenv
load_dotenv()

import csv
import html
import io
import logging
import os
import re
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

import bcrypt
import jwt
import requests
from fastapi import FastAPI, APIRouter, HTTPException, Request, Depends, UploadFile, File
from fastapi.responses import Response
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
SITE_URL = os.environ.get("SITE_URL", "").rstrip("/")

app = FastAPI(title="Starbit Technology API")
api_router = APIRouter(prefix="/api")
logger = logging.getLogger("starbit")

# ---------- Object storage (Emergent objstore) ----------

STORAGE_BASE = (os.environ.get("INTEGRATION_PROXY_URL") or "").strip() or "https://integrations.emergentagent.com"
STORAGE_URL = STORAGE_BASE.rstrip("/") + "/objstore/api/v1/storage"
EMERGENT_KEY = os.environ.get("EMERGENT_LLM_KEY")
APP_NAME = "starbit-electronics"
_storage_key = None

MIME_TYPES = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "gif": "image/gif", "webp": "image/webp", "pdf": "application/pdf",
}


def init_storage(force: bool = False):
    global _storage_key
    if _storage_key and not force:
        return _storage_key
    resp = requests.post(f"{STORAGE_URL}/init", json={"emergent_key": EMERGENT_KEY}, timeout=30)
    resp.raise_for_status()
    _storage_key = resp.json()["storage_key"]
    return _storage_key


def put_object(path: str, data: bytes, content_type: str) -> dict:
    key = init_storage()
    resp = requests.put(
        f"{STORAGE_URL}/objects/{path}",
        headers={"X-Storage-Key": key, "Content-Type": content_type},
        data=data, timeout=120,
    )
    if resp.status_code == 404:
        init_storage(force=True)
        resp = requests.put(
            f"{STORAGE_URL}/objects/{path}",
            headers={"X-Storage-Key": _storage_key, "Content-Type": content_type},
            data=data, timeout=120,
        )
    resp.raise_for_status()
    return resp.json()


def get_object(path: str):
    key = init_storage()
    resp = requests.get(f"{STORAGE_URL}/objects/{path}", headers={"X-Storage-Key": key}, timeout=60)
    resp.raise_for_status()
    return resp.content, resp.headers.get("Content-Type", "application/octet-stream")


# ---------- Auth ----------

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": "admin",
        "exp": datetime.now(timezone.utc) + timedelta(hours=12),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_admin(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = await db.users.find_one({"email": payload.get("email"), "role": "admin"})
    if not user:
        raise HTTPException(status_code=401, detail="Admin not found")
    return {"id": str(user["_id"]), "email": user["email"], "name": user.get("name", "Admin"), "role": "admin"}


class LoginIn(BaseModel):
    email: str
    password: str


@api_router.post("/auth/login")
async def login(body: LoginIn, request: Request):
    email = body.email.strip().lower()
    identifier = f"{request.client.host if request.client else 'unknown'}:{email}"
    attempts = await db.login_attempts.find_one({"identifier": identifier})
    if attempts and attempts.get("count", 0) >= 5:
        locked_since = attempts.get("updated_at", datetime.now(timezone.utc))
        if isinstance(locked_since, datetime) and locked_since.tzinfo is None:
            locked_since = locked_since.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - locked_since < timedelta(minutes=15):
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 15 minutes.")
    user = await db.users.find_one({"email": email, "role": "admin"})
    if not user or not verify_password(body.password, user["password_hash"]):
        await db.login_attempts.update_one(
            {"identifier": identifier},
            {"$inc": {"count": 1}, "$set": {"updated_at": datetime.now(timezone.utc)}},
            upsert=True,
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")
    await db.login_attempts.delete_one({"identifier": identifier})
    token = create_token(str(user["_id"]), email)
    return {"token": token, "user": {"email": email, "name": user.get("name", "Admin"), "role": "admin"}}


@api_router.get("/auth/me")
async def auth_me(admin: dict = Depends(get_admin)):
    return admin


# ---------- Site settings ----------

DEFAULT_SETTINGS = {
    "business_phone": "01341454624",
    "office_address": "1-34/8, 3rd Floor, Batla House, Jamia Nagar, Okhla, New Delhi - 110025, India",
    "business_email": "",
    "instagram_url": "",
    "facebook_url": "",
    "youtube_url": "",
}


@api_router.get("/settings")
async def get_settings():
    doc = await db.settings.find_one({"key": "site"})
    out = dict(DEFAULT_SETTINGS)
    if doc:
        out.update({k: v for k, v in doc.items() if k in DEFAULT_SETTINGS and v is not None})
    return out


class SettingsIn(BaseModel):
    business_phone: Optional[str] = None
    office_address: Optional[str] = None
    business_email: Optional[str] = None
    instagram_url: Optional[str] = None
    facebook_url: Optional[str] = None
    youtube_url: Optional[str] = None


@api_router.put("/admin/settings")
async def update_settings(body: SettingsIn, admin: dict = Depends(get_admin)):
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    data["key"] = "site"
    data["updated_at"] = datetime.now(timezone.utc)
    await db.settings.update_one({"key": "site"}, {"$set": data}, upsert=True)
    return await get_settings()


# ---------- File uploads ----------

@api_router.post("/admin/upload")
async def upload_file(request: Request, file: UploadFile = File(...), admin: dict = Depends(get_admin)):
    ext = (file.filename or "").split(".")[-1].lower() if "." in (file.filename or "") else ""
    if ext not in MIME_TYPES:
        raise HTTPException(status_code=422, detail="Only images (jpg/png/webp/gif) and PDF files are allowed.")
    data = await file.read()
    if len(data) > 15 * 1024 * 1024:
        raise HTTPException(status_code=422, detail="File too large (max 15 MB).")
    path = f"{APP_NAME}/uploads/{uuid.uuid4()}.{ext}"
    result = put_object(path, data, MIME_TYPES[ext])
    await db.files.insert_one({
        "storage_path": result["path"],
        "original_filename": file.filename,
        "content_type": MIME_TYPES[ext],
        "size": result.get("size", len(data)),
        "is_deleted": False,
        "created_at": datetime.now(timezone.utc),
    })
    return {"url": f"/api/files/{result['path']}", "path": result["path"]}


@api_router.get("/files/{path:path}")
async def serve_file(path: str):
    record = await db.files.find_one({"storage_path": path, "is_deleted": False})
    if not record:
        raise HTTPException(status_code=404, detail="File not found")
    data, content_type = get_object(path)
    return Response(content=data, media_type=record.get("content_type", content_type))


# ---------- Products ----------

def slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "product"


AVAILABILITY = ("unknown", "available", "unavailable", "discontinued")


class ProductIn(BaseModel):
    name: str
    model_number: str = ""
    category: str = "cctv"
    subcategory: str = ""
    image: str = ""
    short_description: str = ""
    description: str = ""
    features: List[str] = []
    specs: List[dict] = []
    downloads: List[dict] = []
    status: str = "draft"
    featured: bool = False
    sample: bool = True
    price: Optional[float] = None
    mrp: Optional[float] = None
    price_updated_at: str = ""
    price_note: str = ""
    availability: str = "unknown"
    keywords: List[str] = []
    sticker: List[str] = []
    gallery: List[str] = []
    image_label: str = ""
    seo_title: str = ""
    seo_description: str = ""


def product_to_response(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    return doc


@api_router.get("/products")
async def list_products(request: Request, category: Optional[str] = None, q: Optional[str] = None,
                        all: bool = False, featured: bool = False):
    query = {}
    is_admin = False
    if all:
        try:
            await get_admin(request)
            is_admin = True
        except HTTPException:
            is_admin = False
    if not (all and is_admin):
        query["status"] = "published"
    if category:
        query["category"] = category
    if featured:
        query["featured"] = True
    if q:
        rx = {"$regex": re.escape(q), "$options": "i"}
        query["$or"] = [{"name": rx}, {"model_number": rx}, {"subcategory": rx},
                        {"short_description": rx}, {"category": rx}, {"keywords": rx},
                        {"features": rx}, {"specs.value": rx}, {"specs.key": rx}]
    docs = await db.products.find(query).sort("created_at", -1).to_list(500)
    return [product_to_response(d) for d in docs]


@api_router.get("/products/meta/categories")
async def product_categories():
    pipeline = [
        {"$match": {"status": "published"}},
        {"$group": {"_id": {"category": "$category", "subcategory": "$subcategory"}, "count": {"$sum": 1}}},
    ]
    rows = await db.products.aggregate(pipeline).to_list(200)
    out = {}
    for r in rows:
        cat = r["_id"]["category"]
        sub = r["_id"].get("subcategory") or ""
        out.setdefault(cat, {"count": 0, "subcategories": {}})
        out[cat]["count"] += r["count"]
        if sub:
            out[cat]["subcategories"][sub] = out[cat]["subcategories"].get(sub, 0) + r["count"]
    for cat in out:
        out[cat]["subcategories"] = [{"name": k, "count": v} for k, v in sorted(out[cat]["subcategories"].items())]
    return out


@api_router.get("/products/{slug}")
async def get_product(slug: str):
    doc = await db.products.find_one({"slug": slug})
    if not doc:
        raise HTTPException(status_code=404, detail="Product not found")
    if doc.get("status") != "published":
        raise HTTPException(status_code=404, detail="Product not found")
    related = await db.products.find(
        {"category": doc["category"], "status": "published", "slug": {"$ne": slug}},
        {"name": 1, "slug": 1, "model_number": 1, "image": 1, "short_description": 1,
         "category": 1, "subcategory": 1, "sample": 1, "price": 1, "availability": 1},
    ).limit(4).to_list(4)
    result = product_to_response(doc)
    result["related"] = [product_to_response(r) for r in related]
    return result


def validate_product(data: dict):
    if data.get("availability") not in AVAILABILITY:
        data["availability"] = "unknown"
    if data.get("price") is not None and data["price"] < 0:
        raise HTTPException(status_code=422, detail="Price cannot be negative.")
    if data.get("mrp") is not None and data["mrp"] < 0:
        raise HTTPException(status_code=422, detail="MRP cannot be negative.")


@api_router.post("/admin/products")
async def create_product(body: ProductIn, admin: dict = Depends(get_admin)):
    data = body.model_dump()
    validate_product(data)
    data["slug"] = slugify(f"{data['model_number'] or data['name']}")
    if await db.products.find_one({"slug": data["slug"]}):
        alt = slugify(data["name"])
        data["slug"] = alt if not await db.products.find_one({"slug": alt}) else f"{data['slug']}-{uuid.uuid4().hex[:4]}"
    data["created_at"] = datetime.now(timezone.utc)
    data["updated_at"] = datetime.now(timezone.utc)
    res = await db.products.insert_one(data)
    data["id"] = str(res.inserted_id)
    data.pop("_id", None)
    return data


@api_router.put("/admin/products/{product_id}")
async def update_product(product_id: str, body: ProductIn, admin: dict = Depends(get_admin)):
    from bson import ObjectId
    data = body.model_dump()
    validate_product(data)
    data["updated_at"] = datetime.now(timezone.utc)
    res = await db.products.update_one({"_id": ObjectId(product_id)}, {"$set": data})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    doc = await db.products.find_one({"_id": ObjectId(product_id)})
    return product_to_response(doc)


@api_router.delete("/admin/products/{product_id}")
async def delete_product(product_id: str, admin: dict = Depends(get_admin)):
    from bson import ObjectId
    res = await db.products.delete_one({"_id": ObjectId(product_id)})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"deleted": True}


# ---------- Enquiries ----------

class EnquiryIn(BaseModel):
    type: str = "product"  # product | dealer | general
    name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=8, max_length=20)
    city: str = ""
    business_type: str = ""
    product: str = ""
    product_name: str = ""
    model_number: str = ""
    price_at_enquiry: Optional[float] = None
    message: str = ""


def clean_enquiry(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    if isinstance(doc.get("created_at"), datetime):
        doc["created_at"] = doc["created_at"].isoformat()
    return doc


@api_router.post("/enquiries")
async def create_enquiry(body: EnquiryIn):
    if body.type not in ("product", "dealer", "general"):
        raise HTTPException(status_code=422, detail="Invalid enquiry type")
    data = body.model_dump()
    if not data["product"] and data["product_name"]:
        data["product"] = data["product_name"]
    data["status"] = "new"
    data["created_at"] = datetime.now(timezone.utc)
    res = await db.enquiries.insert_one(data)
    return {"success": True, "id": str(res.inserted_id),
            "message": "Your enquiry has been received. Our team will contact you shortly."}


def filter_enquiries_query(q: Optional[str], type: Optional[str], status: Optional[str]) -> dict:
    query = {}
    if type in ("product", "dealer", "general"):
        query["type"] = type
    if status in ("new", "contacted", "closed"):
        query["status"] = status
    if q:
        rx = {"$regex": re.escape(q), "$options": "i"}
        query["$or"] = [{"name": rx}, {"phone": rx}, {"city": rx},
                        {"product": rx}, {"product_name": rx}, {"model_number": rx}, {"message": rx}]
    return query


@api_router.get("/admin/enquiries")
async def list_enquiries(q: Optional[str] = None, type: Optional[str] = None,
                         status: Optional[str] = None, admin: dict = Depends(get_admin)):
    docs = await db.enquiries.find(filter_enquiries_query(q, type, status)).sort("created_at", -1).to_list(1000)
    return [clean_enquiry(d) for d in docs]


@api_router.get("/admin/enquiries/export")
async def export_enquiries(q: Optional[str] = None, type: Optional[str] = None,
                           status: Optional[str] = None, admin: dict = Depends(get_admin)):
    docs = await db.enquiries.find(filter_enquiries_query(q, type, status)).sort("created_at", -1).to_list(5000)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Date", "Type", "Status", "Name", "Phone", "City", "Business Type",
                     "Product", "Model Number", "Price at Enquiry (INR)", "Message"])
    for d in docs:
        created = d.get("created_at")
        writer.writerow([
            created.strftime("%Y-%m-%d %H:%M") if isinstance(created, datetime) else str(created or ""),
            d.get("type", ""), d.get("status", ""), d.get("name", ""), d.get("phone", ""),
            d.get("city", ""), d.get("business_type", ""), d.get("product", ""),
            d.get("model_number", ""), d.get("price_at_enquiry") if d.get("price_at_enquiry") is not None else "",
            (d.get("message", "") or "").replace("\n", " "),
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=starbit-enquiries.csv"},
    )


@api_router.patch("/admin/enquiries/{enquiry_id}")
async def update_enquiry(enquiry_id: str, request: Request, admin: dict = Depends(get_admin)):
    from bson import ObjectId
    body = await request.json()
    status = body.get("status")
    if status not in ("new", "contacted", "closed"):
        raise HTTPException(status_code=422, detail="Invalid status")
    res = await db.enquiries.update_one({"_id": ObjectId(enquiry_id)}, {"$set": {"status": status}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Enquiry not found")
    return {"success": True}


# ---------- SEO: sitemap ----------

STATIC_ROUTES = [
    "", "cctv-cameras", "led-tvs", "air-coolers", "products",
    "about", "downloads", "contact", "enquiry", "dealer-enquiry",
    "privacy-policy", "terms-and-conditions",
]


@api_router.get("/sitemap.xml")
async def sitemap():
    base = SITE_URL
    urls = []
    for r in STATIC_ROUTES:
        urls.append(f"<url><loc>{html.escape(base + '/' + r)}</loc></url>")
    docs = await db.products.find({"status": "published"}, {"slug": 1, "updated_at": 1}).to_list(2000)
    for d in docs:
        lastmod = ""
        if isinstance(d.get("updated_at"), datetime):
            lastmod = f"<lastmod>{d['updated_at'].date().isoformat()}</lastmod>"
        urls.append(f"<url><loc>{html.escape(base + '/product/' + d['slug'])}</loc>{lastmod}</url>")
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           + "".join(urls) + "</urlset>")
    return Response(content=xml, media_type="application/xml")


@api_router.get("/")
async def root():
    return {"message": "Starbit Technology API"}


# ---------- Seed ----------

IMG = {
    "dome": "https://images.pexels.com/photos/10233086/pexels-photo-10233086.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "bullet": "https://images.pexels.com/photos/27505236/pexels-photo-27505236.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "tv": "https://images.unsplash.com/photo-1773867567872-3ad1fa481082?crop=entropy&cs=srgb&fm=jpg&q=85",
    "tv2": "https://images.pexels.com/photos/28850990/pexels-photo-28850990.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "cam_bullet": "/api/files/starbit-electronics/uploads/d47adf3f-b955-4c76-8936-d011be5e86ee.png",
    "cam_dome": "/api/files/starbit-electronics/uploads/918f6158-eb1e-498f-a669-cc3d15fb29eb.png",
    "cooler": "https://images.pexels.com/photos/16914846/pexels-photo-16914846.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
}

SEED_PRODUCTS = [
    {"name": "Starbit 2.4MP HD Outdoor Bullet Camera (Color VU + Audio)", "model_number": "SB-304P", "category": "cctv",
     "subcategory": "Bullet Cameras", "image": IMG["cam_bullet"], "featured": True,
     "short_description": "2.4MP Full HD outdoor bullet camera with ColorVu full-colour night vision and built-in microphone.",
     "description": "Verified Starbit model.",
     "features": ["2.4MP (1080p Full HD) clarity", "ColorVu full-colour day & night vision", "Built-in high-sensitivity microphone", "IP66 weatherproof outdoor housing", "3.6mm fixed wide-angle lens"],
     "specs": [{"key": "Type", "value": "Bullet (Outdoor)"}, {"key": "Technology", "value": "TVI HD (Analog HD)"}, {"key": "Resolution", "value": "2.4MP (1080p Full HD)"}, {"key": "Lens", "value": "3.6mm Fixed Wide-Angle"}, {"key": "Night Vision", "value": "ColorVu Full Colour Day & Night"}, {"key": "Audio", "value": "Built-in High-Sensitivity Microphone"}, {"key": "Power / Output", "value": "DC 12V 1000mA | PAL / 1.0Vp-p 75"}, {"key": "Enclosure", "value": "IP66 Weatherproof"}, {"key": "Warranty", "value": "1 Year Comprehensive"}],
     "downloads": [], "status": "published", "sample": False, "price": 2999, "mrp": 5999,
     "availability": "available", "price_updated_at": "2026-10-18", "price_note": "Flat 50% OFF on MRP",
     "sticker": ["2.4MP Full HD", "ColorVu Colour Night Vision", "Built-in Audio Mic", "IP66 Outdoor", "1 Year Warranty"],
     "keywords": ["starbit bullet camera", "starbit cctv camera price", "sb-304p"]},
    {"name": "Starbit 2.4MP HD Indoor Dome Camera (Color VU + Audio)", "model_number": "SB-254", "category": "cctv",
     "subcategory": "Dome Cameras", "image": IMG["cam_dome"],
     "short_description": "2.4MP Full HD indoor ceiling dome camera with ColorVu full-colour night vision and built-in mic.",
     "description": "Verified Starbit model.",
     "features": ["2.4MP (1080p Full HD) clarity", "ColorVu full-colour day & night vision", "Built-in high-sensitivity microphone", "Compact indoor ceiling turret dome", "3.6mm fixed HD lens"],
     "specs": [{"key": "Type", "value": "Dome (Indoor Ceiling)"}, {"key": "Technology", "value": "TVI HD (Analog HD)"}, {"key": "Resolution", "value": "2.4MP (1080p Full HD)"}, {"key": "Lens", "value": "3.6mm Fixed HD"}, {"key": "Night Vision", "value": "ColorVu Full Colour Day & Night"}, {"key": "Audio", "value": "Built-in High-Sensitivity Microphone"}, {"key": "Power / Output", "value": "DC 12V 1000mA | PAL / 1.0Vp-p 75"}, {"key": "Enclosure", "value": "Compact Indoor Turret Dome"}, {"key": "Warranty", "value": "1 Year Comprehensive"}],
     "downloads": [], "status": "published", "sample": False, "price": 2999, "mrp": 5999,
     "availability": "available", "price_updated_at": "2026-10-18", "price_note": "Flat 50% OFF on MRP",
     "sticker": ["2.4MP Full HD", "ColorVu Colour Night Vision", "Built-in Audio Mic", "Ceiling Dome", "1 Year Warranty"],
     "keywords": ["starbit dome camera", "starbit cctv dome price", "sb-254"]},
    {"name": "Starbit 5MP Ultra HD IP Bullet Camera (Dual Smart Light + Audio)", "model_number": "SB-280", "category": "cctv",
     "subcategory": "Bullet Cameras", "image": IMG["cam_bullet"], "featured": True,
     "short_description": "5MP Ultra HD IP bullet camera with dual smart light, ColorVu night vision, PoE and built-in audio.",
     "description": "Verified Starbit model.",
     "features": ["5MP Ultra HD (2560 x 1920 / 2880 x 1620)", "ColorVu full-colour night vision + smart dual warm LEDs / IR", "Built-in microphone", "H.265+ / H.264 compression", "PoE (802.3af) + DC 12V", "Heavy-duty IP67 metal housing", "ONVIF Profile S/T"],
     "specs": [{"key": "Type", "value": "Bullet (Outdoor)"}, {"key": "Technology", "value": "Network IP"}, {"key": "Resolution", "value": "5MP Ultra HD (2560 x 1920 / 2880 x 1620)"}, {"key": "Lens", "value": "3.6mm Fixed HD"}, {"key": "Night Vision", "value": "ColorVu + Smart Dual Warm LEDs / IR"}, {"key": "Audio / Codec", "value": "Built-in Mic | H.265+ / H.264"}, {"key": "Network / Power", "value": "RJ-45 10/100M, PoE 802.3af, DC 12V 1000mA"}, {"key": "Compliance", "value": "ONVIF Profile S/T"}, {"key": "Enclosure", "value": "IP67 Metal Weatherproof"}, {"key": "Warranty", "value": "1 Year Comprehensive"}],
     "downloads": [], "status": "published", "sample": False, "price": 3999, "mrp": 7999,
     "availability": "available", "price_updated_at": "2026-10-18", "price_note": "Flat 50% OFF on MRP",
     "sticker": ["5MP Ultra HD", "Dual Smart Light", "PoE + Audio", "IP67 Metal Body", "1 Year Warranty"],
     "keywords": ["starbit 5mp bullet camera", "starbit ip camera price", "sb-280", "starbit poe camera"]},
    {"name": "Starbit 5MP Ultra HD IP Dome Camera (Dual Smart Light + Audio)", "model_number": "SB-254-5MP", "category": "cctv",
     "subcategory": "Dome Cameras", "image": IMG["cam_dome"],
     "short_description": "5MP Ultra HD IP dome camera with ColourVu, smart IR, PoE support and integrated audio.",
     "description": "Verified Starbit model.",
     "features": ["5MP Ultra HD resolution", "ColourVu full colour + smart IR night vision", "Integrated audio microphone", "H.265+ high-efficiency compression", "PoE supported / DC 12V", "Impact-resistant ceiling dome", "ONVIF ready"],
     "specs": [{"key": "Type", "value": "Dome (Ceiling)"}, {"key": "Technology", "value": "Network IP"}, {"key": "Resolution", "value": "5MP Ultra HD"}, {"key": "Lens", "value": "3.6mm Fixed HD"}, {"key": "Night Vision", "value": "ColourVu Full Colour + Smart IR"}, {"key": "Audio / Codec", "value": "Integrated Mic | H.265+"}, {"key": "Network / Power", "value": "RJ-45 LAN, PoE / DC 12V 1000mA"}, {"key": "Compliance", "value": "ONVIF Ready"}, {"key": "Enclosure", "value": "Impact-Resistant Ceiling Dome"}, {"key": "Warranty", "value": "1 Year Comprehensive"}],
     "downloads": [], "status": "published", "sample": False, "price": 4499, "mrp": 8999,
     "availability": "available", "price_updated_at": "2026-10-18", "price_note": "Flat 50% OFF on MRP",
     "sticker": ["5MP Ultra HD", "ColourVu + Smart IR", "PoE + Audio", "H.265+ Codec", "1 Year Warranty"],
     "keywords": ["starbit 5mp dome camera", "starbit ip dome price", "sb-254 5mp"]},
    {"name": "Starbit 8MP 4K Ultra HD IP Bullet Camera (Color VU + Audio)", "model_number": "SB-285", "category": "cctv",
     "subcategory": "Bullet Cameras", "image": IMG["cam_bullet"], "featured": True,
     "short_description": "Flagship 8MP 4K UHD IP bullet camera with F1.0 starlight lens, 24/7 ColorVu and noise-reduction mic.",
     "description": "Verified Starbit model.",
     "features": ["8MP 4K UHD (3840 x 2160) cinema-grade video", "3.6mm 4K starlight lens, F1.0 super aperture", "Flagship ColorVu 24/7 full-colour night vision", "High-fidelity microphone with noise reduction", "H.265+ ultra compression", "PoE + mobile cloud app (P2P remote view)", "Industrial IP67 rugged metal body", "ONVIF compliant"],
     "specs": [{"key": "Type", "value": "Bullet (Outdoor)"}, {"key": "Technology", "value": "4K Network IP"}, {"key": "Resolution", "value": "8MP 4K UHD (3840 x 2160)"}, {"key": "Lens", "value": "3.6mm 4K Starlight, F1.0 Super Aperture"}, {"key": "Night Vision", "value": "Flagship ColorVu 24/7 Full-Color + Warm Fill Light"}, {"key": "Audio", "value": "High-Fidelity Mic with Noise Reduction"}, {"key": "Network / Protocols", "value": "PoE, H.265+, ONVIF, Mobile Cloud App (P2P)"}, {"key": "Power", "value": "DC 12V 1000mA / PoE"}, {"key": "Enclosure", "value": "Industrial IP67 Rugged Metal"}, {"key": "Warranty", "value": "1 Year Comprehensive"}],
     "downloads": [], "status": "published", "sample": False, "price": 4350, "mrp": 8700,
     "availability": "available", "price_updated_at": "2026-10-18", "price_note": "Flat 50% OFF on MRP",
     "sticker": ["8MP 4K UHD", "F1.0 Starlight Lens", "24/7 ColorVu", "PoE + Hi-Fi Audio", "1 Year Warranty"],
     "keywords": ["starbit 4k bullet camera", "starbit 8mp camera price", "sb-285", "starbit 4k cctv"]},
    {"name": "Starbit 8MP 4K Ultra HD IP Dome Camera (Color VU + Audio)", "model_number": "SB-265", "category": "cctv",
     "subcategory": "Dome Cameras", "image": IMG["cam_dome"],
     "short_description": "8MP 4K UHD vandal-resistant eyeball dome with ColorVu, dual illumination and noise-cancelling mic.",
     "description": "Verified Starbit model.",
     "features": ["8MP 4K UHD (3840 x 2160)", "3.6mm 4K high-resolution optical lens", "ColorVu full-colour night vision + smart dual illumination", "High-fidelity noise-cancelling microphone", "H.265+ compression, ONVIF, web & app streaming", "Vandal-resistant compact eyeball dome"],
     "specs": [{"key": "Type", "value": "Eyeball Dome (Ceiling)"}, {"key": "Technology", "value": "4K Network IP"}, {"key": "Resolution", "value": "8MP 4K UHD (3840 x 2160)"}, {"key": "Lens", "value": "3.6mm 4K High-Res Optical"}, {"key": "Night Vision", "value": "ColorVu Full-Color + Smart Dual Illumination"}, {"key": "Audio", "value": "High-Fidelity Noise-Cancelling Mic"}, {"key": "Network / Protocols", "value": "PoE, H.265+, ONVIF, Web & App Streaming"}, {"key": "Power", "value": "DC 12V / PoE"}, {"key": "Enclosure", "value": "Vandal-Resistant Compact Dome"}, {"key": "Warranty", "value": "1 Year Comprehensive"}],
     "downloads": [], "status": "published", "sample": False, "price": 4850, "mrp": 9700,
     "availability": "available", "price_updated_at": "2026-10-18", "price_note": "Flat 50% OFF on MRP",
     "sticker": ["8MP 4K UHD", "ColorVu Dual Light", "PoE + NC Mic", "Vandal Resistant", "1 Year Warranty"],
     "keywords": ["starbit 4k dome camera", "starbit 8mp dome price", "sb-265"]},
    {"name": "Starbit 24\" Standard HD LED TV", "model_number": "SBT24N100", "category": "led-tv",
     "subcategory": "HD Ready", "image": IMG["tv2"], "featured": False,
     "short_description": "24\" (60 cm) Standard HD LED TV with A+ grade panel and PC monitor VGA input.",
     "description": "Verified Starbit model.",
     "features": ["A+ grade panel", "1366 x 768 HD resolution", "16W dual stereo speakers", "PC monitor VGA input"],
     "specs": [{"key": "Screen Size", "value": "24 in (60 cm)"}, {"key": "Resolution", "value": "1366 x 768 HD"},
               {"key": "Audio", "value": "16W Dual Stereo Speakers"}, {"key": "Input", "value": "PC Monitor VGA, HDMI, USB"}],
     "downloads": [], "status": "published", "sample": False, "price": 6500, "mrp": 9999,
     "availability": "available", "price_updated_at": "2026-10-18",
     "sticker": ["Ultra Slim", "Energy Efficient", "PC Monitor Ready", "1 Year Warranty"],
     "keywords": ["starbit 24 inch led tv", "starbit 24 inch led tv price"]},
    {"name": "Starbit 32\" Smart HD LED TV", "model_number": "SBT322G5B", "category": "led-tv",
     "subcategory": "HD Ready Smart", "image": IMG["tv2"], "featured": True,
     "short_description": "32\" (80 cm) Smart HD LED TV with A+ achromatic panel, smart OS and 20W stereo sound.",
     "description": "Verified Starbit model.",
     "features": ["A+ grade achromatic panel", "Smart TV OS with 1 GB RAM + 8 GB ROM", "20W stereo sound", "HDMI & USB playback"],
     "specs": [{"key": "Screen Size", "value": "32 in (80 cm)"}, {"key": "Resolution", "value": "1366 x 768 HD"},
               {"key": "RAM / Storage", "value": "1 GB RAM + 8 GB ROM"}, {"key": "Operating System", "value": "Smart TV OS"},
               {"key": "Audio", "value": "20W Stereo Sound"}],
     "downloads": [], "status": "published", "sample": False, "price": 11339, "mrp": 16199,
     "availability": "available", "price_updated_at": "2026-10-18",
     "sticker": ["A+ Achromatic Panel", "HD Ready", "Smart OS", "1 Year Warranty"],
     "keywords": ["starbit 32 inch led tv", "starbit 32 inch smart tv price"]},
    {"name": "Starbit 43\" Smart Soundbar LED TV", "model_number": "SBT432G5B", "category": "led-tv",
     "subcategory": "Full HD Smart", "image": IMG["tv2"], "featured": False,
     "short_description": "43\" (108 cm) Full HD Smart LED TV with integrated front-firing cinematic soundbar.",
     "description": "Verified Starbit model.",
     "features": ["Full HD 1080p resolution", "Integrated front-firing cinematic soundbar", "178-degree wide viewing angle"],
     "specs": [{"key": "Screen Size", "value": "43 in (108 cm)"}, {"key": "Resolution", "value": "Full HD 1920 x 1080"},
               {"key": "Viewing Angle", "value": "178° wide"}, {"key": "Audio", "value": "Integrated Front-Firing Cinematic Soundbar"}],
     "downloads": [], "status": "published", "sample": False, "price": 19459, "mrp": 27799,
     "availability": "available", "price_updated_at": "2026-10-18",
     "sticker": ["Integrated Soundbar", "Full HD 1080p", "178° Wide View", "1 Year Warranty"],
     "keywords": ["starbit 43 inch led tv", "starbit 43 inch led tv price", "starbit soundbar tv"]},
    {"name": "Starbit 43\" Smart TV (Google Assistant Voice Remote)", "model_number": "VTL43VC1000DX", "category": "led-tv",
     "subcategory": "Full HD Smart", "image": IMG["tv2"], "featured": True,
     "short_description": "43\" (108 cm) Full HD Smart TV with Bluetooth voice remote, Google Assistant and 24W Dolby Audio.",
     "description": "Verified Starbit model.",
     "features": ["A+ grade achromatic panel", "Full HD 1920 x 1080", "Bluetooth voice remote with Google Assistant", "24W Dolby Audio"],
     "specs": [{"key": "Screen Size", "value": "43 in (108 cm)"}, {"key": "Resolution", "value": "Full HD 1920 x 1080"},
               {"key": "Remote", "value": "Bluetooth Voice Remote with Google Assistant"}, {"key": "Audio", "value": "24W Dolby Audio"}],
     "downloads": [], "status": "published", "sample": False, "price": 19499, "mrp": 28999,
     "availability": "available", "price_updated_at": "2026-10-18",
     "sticker": ["Voice Remote Assistant", "A+ Achromatic Panel", "FHD 1080p", "1 Year Warranty"],
     "keywords": ["starbit 43 inch smart tv", "starbit voice remote tv price"]},
    {"name": "Starbit 55\" 4K Ultra HD Quantum QLED webOS Gaming TV", "model_number": "SBT55Q4K-PRO", "category": "led-tv",
     "subcategory": "QLED 4K webOS", "image": IMG["tv2"], "featured": True,
     "short_description": "55\" (140 cm) 4K Quantum Dot QLED with webOS Hub, 3 GB RAM + 16 GB ROM and Magic Motion Remote.",
     "description": "Verified Starbit flagship QLED model.",
     "features": ["4K Ultra HD Quantum Dot QLED (3840 x 2160)", "Quantum HDR10+ with 100% Color Volume", "3 GB RAM + 16 GB ROM",
                  "Next-Gen Quad-Core Quantum Gaming Processor (ALLM, MEMC)", "webOS Hub with ThinQ AI",
                  "Starbit Magic Motion Remote (Air Mouse & Voice)", "30W Dolby Audio box speakers"],
     "specs": [{"key": "Screen Size", "value": "55 in (140 cm)"}, {"key": "Display", "value": "4K Ultra HD Quantum Dot QLED, 3840 x 2160"},
               {"key": "HDR", "value": "Quantum HDR10+, 100% Color Volume"}, {"key": "RAM / Storage", "value": "3 GB RAM + 16 GB ROM"},
               {"key": "Processor", "value": "Quad-Core Quantum Gaming Processor with GPU"},
               {"key": "Gaming", "value": "Low-Latency Game Mode, ALLM, MEMC 60Hz/120Hz"},
               {"key": "Operating System", "value": "webOS Hub with ThinQ AI"},
               {"key": "Remote", "value": "Starbit Magic Motion Remote (Air Mouse & Voice)"},
               {"key": "Audio", "value": "30W Dolby Audio Box Speakers"}, {"key": "Ports", "value": "HDMI 2.1 eARC, USB, Optical, LAN, AV"}],
     "downloads": [], "status": "published", "sample": False, "price": 34999, "mrp": 69999,
     "availability": "available", "price_updated_at": "2026-10-18",
     "sticker": ["QLED 4K", "Quantum Dot Technology", "3GB RAM + 16GB ROM", "Gaming Processor", "webOS Hub", "Magic Remote"],
     "keywords": ["starbit 55 inch qled tv", "starbit 55 inch 4k tv price", "starbit qled"]},
    {"name": "Starbit 65\" 4K Ultra HD Quantum QLED webOS Gaming TV", "model_number": "SBT65Q4K-PRO", "category": "led-tv",
     "subcategory": "QLED 4K webOS", "image": IMG["tv2"], "featured": False,
     "short_description": "65\" (165 cm) 4K Quantum Dot QLED, frameless metallic body, MEMC gaming engine and webOS Hub.",
     "description": "Verified Starbit flagship QLED model.",
     "features": ["4K Ultra HD Quantum Dot QLED (3840 x 2160)", "MEMC Gaming Engine", "Frameless metallic body",
                  "3 GB RAM + 16 GB ROM", "webOS Hub with ThinQ AI", "Starbit Magic Motion Remote", "30W Dolby Audio & DTS Virtual:X"],
     "specs": [{"key": "Screen Size", "value": "65 in (165 cm)"}, {"key": "Display", "value": "4K Ultra HD Quantum Dot QLED, 3840 x 2160"},
               {"key": "Motion", "value": "MEMC Gaming Engine"}, {"key": "Body", "value": "Frameless Metallic"},
               {"key": "RAM / Storage", "value": "3 GB RAM + 16 GB ROM"}, {"key": "Operating System", "value": "webOS Hub"},
               {"key": "Audio", "value": "30W Dolby Audio & DTS Virtual:X"}, {"key": "Ports", "value": "HDMI 2.1 eARC, USB, Optical, LAN, AV"}],
     "downloads": [], "status": "published", "sample": False, "price": 44999, "mrp": 89999,
     "availability": "available", "price_updated_at": "2026-10-18",
     "sticker": ["65 Inch QLED Cinema", "Quantum Dot 4K", "3GB RAM + 16GB ROM", "Gaming Engine", "webOS Hub", "Magic Remote"],
     "keywords": ["starbit 65 inch qled tv", "starbit 65 inch 4k tv price"]},
    {"name": "Starbit 75\" 4K Ultra HD Flagship Quantum QLED webOS Gaming TV", "model_number": "SBT75Q4K-PRO", "category": "led-tv",
     "subcategory": "QLED 4K webOS", "image": IMG["tv2"], "featured": True,
     "short_description": "75\" (190 cm) flagship 4K Quantum Dot QLED with Quantum Matrix Contrast and 40W cinema sound.",
     "description": "Verified Starbit flagship QLED model.",
     "features": ["4K Ultra HD Flagship Quantum Dot QLED (3840 x 2160)", "Quantum Matrix Contrast", "3 GB RAM + 16 GB ROM",
                  "Next-Gen Quantum High-Speed Gaming Processor", "webOS Hub with AI Picture & Sound Pro",
                  "Starbit Magic Motion Remote", "40W cinema sound system with deep bass"],
     "specs": [{"key": "Screen Size", "value": "75 in (190 cm)"}, {"key": "Display", "value": "4K Ultra HD Flagship Quantum Dot QLED, 3840 x 2160"},
               {"key": "Contrast", "value": "Quantum Matrix Contrast"}, {"key": "RAM / Storage", "value": "3 GB RAM + 16 GB ROM"},
               {"key": "Processor", "value": "Next-Gen Quantum High-Speed Gaming Processor"},
               {"key": "Operating System", "value": "webOS Hub with AI Picture & Sound Pro"},
               {"key": "Audio", "value": "40W Cinema Sound System with Deep Bass"}, {"key": "Ports", "value": "HDMI 2.1 eARC, USB, Optical, LAN, AV"}],
     "downloads": [], "status": "published", "sample": False, "price": 64999, "mrp": 129999,
     "availability": "available", "price_updated_at": "2026-10-18",
     "sticker": ["75 Inch Flagship QLED", "Quantum Dot 4K", "3GB RAM + 16GB ROM", "Quantum Gaming Processor", "webOS Hub", "Magic Remote"],
     "keywords": ["starbit 75 inch qled tv", "starbit 75 inch 4k tv price", "starbit flagship tv"]},
    {"name": "Starbit 70L Desert Air Cooler", "model_number": "SB-AC70D", "category": "air-cooler",
     "subcategory": "Desert Coolers", "image": IMG["cooler"],
     "short_description": "High-capacity desert air cooler with honeycomb pads for large rooms.",
     "description": "Illustrative sample listing. Specifications pending official verification by Starbit Technology.",
     "features": ["70 L water tank", "Honeycomb cooling pads", "Powerful air throw", "Castor wheels"],
     "specs": [{"key": "Tank Capacity", "value": "70 L"}, {"key": "Cooling Media", "value": "Honeycomb pads"},
               {"key": "Body", "value": "ABS plastic"}, {"key": "Mobility", "value": "Castor wheels"}],
     "downloads": [], "status": "published", "sample": True},
    {"name": "Starbit 36L Tower Air Cooler", "model_number": "SB-AC36T", "category": "air-cooler",
     "subcategory": "Tower Coolers", "image": IMG["cooler"],
     "short_description": "Slim tower air cooler for personal and medium rooms with elegant design.",
     "description": "Illustrative sample listing. Specifications pending official verification by Starbit Technology.",
     "features": ["36 L water tank", "Space-saving tower design", "Ice chamber", "3-speed control"],
     "specs": [{"key": "Tank Capacity", "value": "36 L"}, {"key": "Form Factor", "value": "Tower"},
               {"key": "Speed Settings", "value": "3"}, {"key": "Ice Chamber", "value": "Yes"}],
     "downloads": [], "status": "published", "sample": True},
]


async def seed_admin():
    email = os.environ.get("ADMIN_EMAIL", "admin@example.com").strip().lower()
    password = os.environ.get("ADMIN_PASSWORD", "admin123")
    existing = await db.users.find_one({"email": email})
    if existing is None:
        await db.users.insert_one({
            "email": email, "password_hash": hash_password(password),
            "name": "Starbit Admin", "role": "admin",
            "created_at": datetime.now(timezone.utc),
        })
        logger.info("Admin account seeded")
    elif not verify_password(password, existing["password_hash"]):
        await db.users.update_one({"email": email}, {"$set": {"password_hash": hash_password(password)}})
        logger.info("Admin password synced")


async def seed_products():
    count = await db.products.count_documents({})
    if count > 0:
        return
    for p in SEED_PRODUCTS:
        p["slug"] = slugify(f"{p['model_number'] or p['name']}")
        p.setdefault("seo_title", "")
        p.setdefault("seo_description", "")
        p.setdefault("price", None)
        p.setdefault("mrp", None)
        p.setdefault("price_updated_at", "")
        p.setdefault("price_note", "")
        p.setdefault("availability", "unknown")
        p.setdefault("keywords", [])
        p.setdefault("sticker", [])
        p["created_at"] = datetime.now(timezone.utc)
        p["updated_at"] = datetime.now(timezone.utc)
        await db.products.insert_one(p)
    logger.info("Seeded %d sample products", len(SEED_PRODUCTS))


async def seed_settings():
    existing = await db.settings.find_one({"key": "site"})
    if not existing:
        await db.settings.insert_one({"key": "site", **DEFAULT_SETTINGS,
                                      "updated_at": datetime.now(timezone.utc)})
        logger.info("Site settings seeded")


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.login_attempts.create_index("identifier")
    await db.products.create_index("slug", unique=True)
    await db.products.create_index("category")
    await seed_admin()
    await seed_products()
    await seed_settings()
    try:
        init_storage()
        logger.info("Object storage initialized")
    except Exception as e:
        logger.error("Storage init failed: %s", e)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
