import os
import hashlib
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import (
    User, Listing, Payment, ViewEvent,
    SignupRequest, LoginRequest, CreateListingRequest,
    SearchQuery, CheckoutRequest, AdminFlagAction, KATEGORITE
)

import re

app = FastAPI(title="Tregu Minimal - Shqip")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shërbe skedarë të ngarkuar (placeholder - përdor ruajtje me URL për demo)
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Lista e domenëve të përkohshëm që bllokohen (shembull)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "trashmail.com", "tempmail.com", "sharklasers.com",
}

# Utilities

def hash_ip(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def device_or_ip_key(ip: str, fp: Optional[str]) -> str:
    return hashlib.sha256(f"{ip}|{fp or ''}".encode()).hexdigest()


def make_listing_hash(title: str, desc: str, images: List[str]) -> str:
    norm = re.sub(r"\s+", " ", (title + "|" + desc).strip().lower())
    imgs = "|".join(sorted(images))
    return hashlib.sha256((norm + "|" + imgs).encode()).hexdigest()


# Seed data endpoint (idempotent)
@app.post("/seed")
async def seed():
    if db is None:
        raise HTTPException(status_code=500, detail="Baza e të dhënave nuk është gati")
    # Krijo kategori dokument nëse duhet (opsionale)
    # Krijo disa përdorues dhe njoftime shembull
    if db["user"].count_documents({"email": "demo@shembull.com"}) == 0:
        u = {
            "emri": "Përdorues Demo",
            "email": "demo@shembull.com",
            "fjalekalimi_hash": hash_password("demo1234"),
            "verifikuar": True,
            "eshte_admin": True,
            "krijuar_me": datetime.utcnow(),
        }
        db["user"].insert_one(u)
        user_id = str(u.get("_id"))
        demo_listings = [
            {
                "titulli": "Golf 7 2016, gjendje shume e mire",
                "pershkrimi": "Makina është e mirëmbajtur, 150,000 km, naftë.",
                "cmimi": 9500,
                "lokacioni": "Tiranë",
                "kategoria": "Automjete",
                "imazhe": [],
                "kontakt": "demo@shembull.com",
                "user_id": user_id,
                "eshte_veçuar": True,
                "statusi": "aktiv",
                "krijuar_me": datetime.utcnow(),
                "perditesuar_me": datetime.utcnow(),
            },
            {
                "titulli": "Apartament 2+1 me qira, Don Bosco",
                "pershkrimi": "Mobiluar plotësisht, kati i 4-t, ashensor.",
                "cmimi": 450,
                "lokacioni": "Tiranë",
                "kategoria": "Banesa",
                "imazhe": [],
                "kontakt": "demo@shembull.com",
                "user_id": user_id,
                "eshte_veçuar": False,
                "statusi": "aktiv",
                "krijuar_me": datetime.utcnow(),
                "perditesuar_me": datetime.utcnow(),
            },
            {
                "titulli": "iPhone 13 Pro, 256GB si i ri",
                "pershkrimi": "Pa asnjë shenjë përdorimi, ngjyra grafit.",
                "cmimi": 650,
                "lokacioni": "Durrës",
                "kategoria": "Elektronika",
                "imazhe": [],
                "kontakt": "demo@shembull.com",
                "user_id": user_id,
                "eshte_veçuar": False,
                "statusi": "aktiv",
                "krijuar_me": datetime.utcnow(),
                "perditesuar_me": datetime.utcnow(),
            },
        ]
        for l in demo_listings:
            l["permbledhje_hash"] = make_listing_hash(l["titulli"], l["pershkrimi"], l["imazhe"])
            db["listing"].insert_one(l)
    return {"mesazh": "Të dhënat fillestare u vendosën."}


# Autentikim bazik: regjistrim, hyrje
@app.post("/auth/signup")
async def signup(req: SignupRequest, request: Request):
    host = request.client.host if request.client else ""
    domen = req.email.split("@")[-1].lower()
    if domen in DISPOSABLE_DOMAINS:
        raise HTTPException(status_code=400, detail="Email i përkohshëm nuk lejohet.")

    # rate-limit për signup
    key = device_or_ip_key(host, req.device_fingerprint)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    rl = db["ratelimit"].find_one({"lloj": "signup", "dita": today, "key": key})
    if rl and rl.get("numri", 0) >= 5:
        raise HTTPException(status_code=429, detail="Shumë tentativa regjistrimi. Provoni më vonë.")

    if db["user"].find_one({"email": req.email}):
        raise HTTPException(status_code=400, detail="Ky email është i regjistruar.")

    user = {
        "emri": req.emri,
        "email": req.email,
        "fjalekalimi_hash": hash_password(req.fjalekalimi),
        "verifikuar": False,
        "eshte_admin": False,
        "krijuar_me": datetime.utcnow(),
        "ip_krijimi": host,
        "device_fingerprint": req.device_fingerprint,
        "listing_count": 0,
    }
    res = db["user"].insert_one(user)

    # për qëllime demo: kthejmë token verifikimi fake
    token = hashlib.sha256(f"{str(res.inserted_id)}|{datetime.utcnow()}".encode()).hexdigest()
    db["verificationtoken"].insert_one({
        "user_id": str(res.inserted_id),
        "token": token,
        "skadon_me": datetime.utcnow() + timedelta(hours=24),
        "krijuar_me": datetime.utcnow(),
    })

    db["ratelimit"].update_one(
        {"lloj": "signup", "dita": today, "key": key},
        {"$inc": {"numri": 1}},
        upsert=True,
    )

    return {"mesazh": "Llogaria u krijua. Ju lutem verifikoni emailin.", "verification_token": token}


@app.post("/auth/verify")
async def verify_email(token: str):
    vt = db["verificationtoken"].find_one({"token": token})
    if not vt:
        raise HTTPException(status_code=400, detail="Token i pavlefshëm.")
    if vt["skadon_me"] < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Token i skaduar.")

    db["user"].update_one({"_id": vt["user_id"]}, {"$set": {"verifikuar": True}})
    db["verificationtoken"].delete_one({"_id": vt["_id"]})
    return {"mesazh": "Emaili u verifikua me sukses."}


@app.post("/auth/login")
async def login(req: LoginRequest):
    u = db["user"].find_one({"email": req.email})
    if not u or u.get("fjalekalimi_hash") != hash_password(req.fjalekalimi):
        raise HTTPException(status_code=401, detail="Kredenciale të pasakta.")
    if not u.get("verifikuar", False):
        raise HTTPException(status_code=403, detail="Ju lutem verifikoni emailin përpara hyrjes.")
    # Simple session token DEMO (jo JWT për thjeshtësi)
    token = hashlib.sha256(f"{u['_id']}|{datetime.utcnow()}".encode()).hexdigest()
    db["session"].insert_one({"user_id": str(u["_id"]), "token": token, "krijuar_me": datetime.utcnow()})
    return {"mesazh": "Hyrja u krye me sukses.", "token": token, "user_id": str(u["_id"]) }


# Middleware i thjeshtë për të gjetur user nga header Bearer
async def get_user_from_token(request: Request) -> Optional[Dict[str, Any]]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
        s = db["session"].find_one({"token": token})
        if s:
            u = db["user"].find_one({"_id": s["user_id"]})
            return u
    return None


# Krijo njoftim (me monetizim: i pari falas, pasuesit me pagesë)
@app.post("/listings")
async def create_listing(req: CreateListingRequest, request: Request, user: Dict[str, Any] = Depends(get_user_from_token)):
    if not user:
        raise HTTPException(status_code=401, detail="Kërkohet hyrja.")
    if not user.get("verifikuar", False):
        raise HTTPException(status_code=403, detail="Verifikoni emailin përpara postimit.")

    host = request.client.host if request.client else ""
    # Ratelimit bazik per krijim
    today = datetime.utcnow().strftime("%Y-%m-%d")
    key = device_or_ip_key(host, req.device_fingerprint)
    rl = db["ratelimit"].find_one({"lloj": "create_listing", "dita": today, "key": key})
    if rl and rl.get("numri", 0) >= 20:
        raise HTTPException(status_code=429, detail="Shumë njoftime të krijuara sot. Provoni më vonë.")

    # Kontrollo duplikatet
    lhash = make_listing_hash(req.titulli, req.pershkrimi, req.imazhe)
    existing = db["listing"].find_one({"permbledhje_hash": lhash, "user_id": str(user["_id"])})
    flamuruar = False
    flamur_arsye = None
    if existing:
        flamuruar = True
        flamur_arsye = "Përmbajtje e ngjashme/duplikat u zbulua"

    # Monetizimi: njoftimi i parë falas
    listing_count = user.get("listing_count", 0)
    eshte_veçuar = False

    if listing_count >= 1:
        # duhet pagesë - vendos status pending deri në pagesë (thjesht për demo do lejom por shënojmë si jo të veçuar)
        eshte_veçuar = False
    
    doc = {
        "titulli": req.titulli,
        "pershkrimi": req.pershkrimi,
        "cmimi": req.cmimi,
        "lokacioni": req.lokacioni,
        "kategoria": req.kategoria,
        "imazhe": req.imazhe,
        "kontakt": req.kontakt,
        "user_id": str(user["_id"]),
        "eshte_veçuar": eshte_veçuar,
        "statusi": "aktiv",
        "shikime": 0,
        "klikime_kontakt": 0,
        "pozicioni_mesatar": 0,
        "shfaqje_total": 0,
        "flamuruar": flamuruar,
        "flamur_arsye": flamur_arsye,
        "krijuar_me": datetime.utcnow(),
        "perditesuar_me": datetime.utcnow(),
        "permbledhje_hash": lhash,
    }
    r = db["listing"].insert_one(doc)

    db["user"].update_one({"_id": user["_id"]}, {"$inc": {"listing_count": 1}})
    db["ratelimit"].update_one(
        {"lloj": "create_listing", "dita": today, "key": key},
        {"$inc": {"numri": 1}},
        upsert=True,
    )
    return {"mesazh": "Njoftimi u krijua.", "id": str(r.inserted_id)}


@app.get("/listings")
async def search_listings(q: Optional[str] = None, kategoria: Optional[str] = None, min_cmimi: Optional[float] = None,
                          max_cmimi: Optional[float] = None, lokacioni: Optional[str] = None, faqja: int = 1, madhesia: int = 12,
                          rendit: Optional[str] = "me_te_veçuarat"):
    filt: Dict[str, Any] = {"statusi": "aktiv"}
    if q:
        filt["$text"] = {"$search": q}
    if kategoria:
        filt["kategoria"] = kategoria
    if lokacioni:
        filt["lokacioni"] = {"$regex": lokacioni, "$options": "i"}
    if min_cmimi is not None or max_cmimi is not None:
        c: Dict[str, Any] = {}
        if min_cmimi is not None:
            c["$gte"] = min_cmimi
        if max_cmimi is not None:
            c["$lte"] = max_cmimi
        filt["cmimi"] = c

    sort = [("eshte_veçuar", -1), ("krijuar_me", -1)]
    if rendit == "cmimi_nga_i_uleti":
        sort = [("eshte_veçuar", -1), ("cmimi", 1)]
    elif rendit == "cmimi_nga_i_larti":
        sort = [("eshte_veçuar", -1), ("cmimi", -1)]
    elif rendit == "me_te_rejat":
        sort = [("eshte_veçuar", -1), ("krijuar_me", -1)]

    skip = max(0, (faqja - 1) * madhesia)
    cursor = db["listing"].find(filt).sort(sort).skip(skip).limit(madhesia)
    items = []
    for d in cursor:
        d["_id"] = str(d["_id"]) 
        items.append(d)
    total = db["listing"].count_documents(filt)
    return {"items": items, "total": total, "faqja": faqja, "madhesia": madhesia}


@app.get("/listings/{listing_id}")
async def get_listing(listing_id: str):
    d = db["listing"].find_one({"_id": listing_id})
    if not d:
        raise HTTPException(status_code=404, detail="Nuk u gjet njoftimi")
    db["viewevent"].insert_one({"listing_id": listing_id, "lloj": "view", "krijuar_me": datetime.utcnow()})
    d["_id"] = str(d["_id"]) 
    return d


@app.put("/listings/{listing_id}")
async def update_listing(listing_id: str, body: Dict[str, Any], user: Dict[str, Any] = Depends(get_user_from_token)):
    if not user:
        raise HTTPException(status_code=401, detail="Kërkohet hyrja.")
    l = db["listing"].find_one({"_id": listing_id})
    if not l or l.get("user_id") != str(user["_id"]):
        raise HTTPException(status_code=404, detail="Njoftimi nuk u gjet ose nuk keni leje.")
    body["perditesuar_me"] = datetime.utcnow()
    db["listing"].update_one({"_id": listing_id}, {"$set": body})
    return {"mesazh": "Njoftimi u përditësua."}


@app.delete("/listings/{listing_id}")
async def delete_listing(listing_id: str, user: Dict[str, Any] = Depends(get_user_from_token)):
    if not user:
        raise HTTPException(status_code=401, detail="Kërkohet hyrja.")
    l = db["listing"].find_one({"_id": listing_id})
    if not l or l.get("user_id") != str(user["_id"]):
        raise HTTPException(status_code=404, detail="Njoftimi nuk u gjet ose nuk keni leje.")
    db["listing"].delete_one({"_id": listing_id})
    return {"mesazh": "Njoftimi u fshi."}


@app.post("/track/{listing_id}/contact")
async def track_contact(listing_id: str):
    db["listing"].update_one({"_id": listing_id}, {"$inc": {"klikime_kontakt": 1}})
    db["viewevent"].insert_one({"listing_id": listing_id, "lloj": "contact_click", "krijuar_me": datetime.utcnow()})
    return {"mesazh": "U regjistrua klikimi i kontaktit"}


# Pagesa – DEMO: simulim i checkout dhe statusit
CMIMET = {"standard": 299, "featured": 799}  # në cent EUR

@app.post("/checkout")
async def checkout(req: CheckoutRequest, user: Dict[str, Any] = Depends(get_user_from_token)):
    if not user:
        raise HTTPException(status_code=401, detail="Kërkohet hyrja.")
    l = db["listing"].find_one({"_id": req.listing_id, "user_id": str(user["_id"])})
    if not l:
        raise HTTPException(status_code=404, detail="Njoftimi nuk u gjet.")
    shuma = CMIMET[req.plani]
    pay = {
        "user_id": str(user["_id"]),
        "listing_id": req.listing_id,
        "plani": req.plani,
        "shuma": shuma,
        "monedha": "eur",
        "metoda": "simuluar",
        "statusi": "success",
        "krijuar_me": datetime.utcnow(),
    }
    db["payment"].insert_one(pay)
    if req.plani == "featured":
        db["listing"].update_one({"_id": req.listing_id}, {"$set": {"eshte_veçuar": True}})
    return {"mesazh": "Pagesa u krye me sukses.", "shuma": shuma}


# Paneli i përdoruesit – statistika të thjeshta
@app.get("/dashboard")
async def dashboard(user: Dict[str, Any] = Depends(get_user_from_token)):
    if not user:
        raise HTTPException(status_code=401, detail="Kërkohet hyrja.")
    listings = list(db["listing"].find({"user_id": str(user["_id"])}))
    for l in listings:
        l["_id"] = str(l["_id"]) 
        # llogaritje baze per krahasim me mesataren e kategorisë
        cat = l.get("kategoria")
        cat_docs = db["listing"].find({"kategoria": cat})
        cat_views = [d.get("shikime", 0) for d in cat_docs]
        mesatare = (sum(cat_views) / len(cat_views)) if cat_views else 0
        l["krahasim_me_kategorine"] = {
            "mesatare_kategorise": mesatare,
            "ndryshim": l.get("shikime", 0) - mesatare
        }
    return {"listings": listings}


# Admin – listim i flamuruar, bllokim përdoruesish, menaxhim pagesash
@app.get("/admin/flagged")
async def admin_flagged(user: Dict[str, Any] = Depends(get_user_from_token)):
    if not user or not user.get("eshte_admin", False):
        raise HTTPException(status_code=403, detail="Leje e pamjaftueshme.")
    items = list(db["listing"].find({"flamuruar": True}))
    for i in items:
        i["_id"] = str(i["_id"]) 
    return {"items": items}


@app.post("/admin/flag-action")
async def admin_flag_action(body: AdminFlagAction, user: Dict[str, Any] = Depends(get_user_from_token)):
    if not user or not user.get("eshte_admin", False):
        raise HTTPException(status_code=403, detail="Leje e pamjaftueshme.")
    if body.veprimi == "hiq_flamurin":
        db["listing"].update_one({"_id": body.listing_id}, {"$set": {"flamuruar": False, "flamur_arsye": None}})
    elif body.veprimi == "pezullo":
        db["listing"].update_one({"_id": body.listing_id}, {"$set": {"statusi": "pezulluar"}})
    return {"mesazh": "U aplikua veprimi."}


@app.get("/schema")
async def schema_export():
    return {
        "models": {
            "user": User.model_json_schema(),
            "listing": Listing.model_json_schema(),
            "payment": Payment.model_json_schema(),
        },
        "kategorite": KATEGORITE,
    }


@app.get("/")
async def root():
    return {"mesazh": "Backend në punë – API shqiptare për treg njoftimesh."}


@app.get("/test")
async def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
