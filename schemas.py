"""
Database Schemas for the Craigslist-like platform (in Albanian)

Each Pydantic model corresponds to a MongoDB collection (collection name is the lowercase class name).
"""
from __future__ import annotations
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Literal, Dict, Any
from datetime import datetime

# Kategori te paracaktuara
KATEGORITE = [
    "Automjete",
    "Banesa",
    "Elektronika",
    "Shërbime",
    "Punë",
    "Pajisje Shtëpie",
    "Të tjera",
]

class User(BaseModel):
    emri: str = Field(..., description="Emri i plotë")
    email: EmailStr = Field(..., description="Adresa e emailit")
    fjalekalimi_hash: str = Field(..., description="Hash i fjalëkalimit")
    verifikuar: bool = Field(False, description="A është emaili verifikuar")
    eshte_admin: bool = Field(False, description="A është përdorues admin")
    krijuar_me: datetime = Field(default_factory=datetime.utcnow)
    ip_krijimi: Optional[str] = None
    device_fingerprint: Optional[str] = None
    
class VerificationToken(BaseModel):
    user_id: str
    token: str
    skadon_me: datetime
    krijuar_me: datetime = Field(default_factory=datetime.utcnow)

class Listing(BaseModel):
    titulli: str
    pershkrimi: str
    cmimi: float = Field(ge=0)
    lokacioni: str
    kategoria: Literal[tuple(KATEGORITE)]
    imazhe: List[str] = []  # url imazhesh
    kontakt: str  # mund të jetë email, telefon ose link kontakt
    user_id: str
    eshte_veçuar: bool = False
    statusi: Literal["aktiv", "pezulluar", "fshire"] = "aktiv"
    shikime: int = 0
    klikime_kontakt: int = 0
    pozicioni_mesatar: float = 0.0
    shfaqje_total: int = 0
    flamuruar: bool = False
    flamur_arsye: Optional[str] = None
    krijuar_me: datetime = Field(default_factory=datetime.utcnow)
    perditesuar_me: datetime = Field(default_factory=datetime.utcnow)
    permbledhje_hash: Optional[str] = None  # per detektim duplikatesh

class Payment(BaseModel):
    user_id: str
    listing_id: Optional[str] = None
    plani: Literal["standard", "featured"]
    shuma: int  # në cent
    monedha: str = "eur"
    metoda: Literal["stripe", "simuluar"] = "simuluar"
    statusi: Literal["success", "pending", "failed"] = "pending"
    checkout_session_id: Optional[str] = None
    krijuar_me: datetime = Field(default_factory=datetime.utcnow)

class ViewEvent(BaseModel):
    listing_id: str
    user_id: Optional[str] = None
    ip: Optional[str] = None
    lloj: Literal["view", "contact_click"]
    krijuar_me: datetime = Field(default_factory=datetime.utcnow)

class RateLimit(BaseModel):
    lloj: Literal["signup", "create_listing"]
    ip_hash: str
    device_fingerprint: Optional[str] = None
    numri: int = 0
    dita: str  # YYYY-MM-DD

# Skema për kërkesa/ përgjigje
class SignupRequest(BaseModel):
    emri: str
    email: EmailStr
    fjalekalimi: str
    device_fingerprint: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    fjalekalimi: str

class CreateListingRequest(BaseModel):
    titulli: str
    pershkrimi: str
    cmimi: float
    lokacioni: str
    kategoria: Literal[tuple(KATEGORITE)]
    imazhe: List[str] = []
    kontakt: str
    device_fingerprint: Optional[str] = None

class SearchQuery(BaseModel):
    q: Optional[str] = None
    kategoria: Optional[str] = None
    min_cmimi: Optional[float] = None
    max_cmimi: Optional[float] = None
    lokacioni: Optional[str] = None
    faqja: int = 1
    madhesia: int = 12
    rendit: Optional[Literal["me_te_rejat", "cmimi_nga_i_uleti", "cmimi_nga_i_larti", "me_te_veçuarat"]] = "me_te_veçuarat"

class CheckoutRequest(BaseModel):
    listing_id: str
    plani: Literal["standard", "featured"]

class AdminFlagAction(BaseModel):
    listing_id: str
    veprimi: Literal["hiq_flamurin", "pezullo"]
    arsye: Optional[str] = None

class SchemaExport(BaseModel):
    """Ndihmë për inspektim në mjedisin e zhvillimit"""
    models: Dict[str, Any]
