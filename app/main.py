from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm

from app.core.database import engine
from app.models.user import Base
from app.api.v1.auth import router as auth_router
from app.core.security import get_current_user, create_access_token, verify_password, get_password_hash
from app.schemas.user import UserCreate, UserOut
from sqlalchemy.orm import Session
from app.core.database import get_db
from typing import Annotated

# Create tables on startup (development only)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="JWT Auth API",
    description="JWT + PostgreSQL Authentication with HTML UI",
    version="1.0"
)

# Jinja2 templates for HTML pages
templates = Jinja2Templates(directory="templates")

# Include API router
app.include_router(auth_router, prefix="/api/v1", tags=["auth"])

# ==================== HTML UI Routes ====================

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# ==================== Form Submission Handlers ====================

@app.post("/register-form")
async def handle_register_form(
    request: Request,
    username: str = Form(...),
    email: str = Form(None),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if username exists
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Username already taken"}
        )

    hashed_password = get_password_hash(password)
    new_user = User(
        username=username,
        email=email,
        hashed_password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Redirect to login after success
    return RedirectResponse(url="/login", status_code=303)


@app.post("/login-form")
async def handle_login_form(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password"}
        )

    # Create token
    access_token = create_access_token(data={"sub": user.username})
    
    # Redirect to /me with token in query (simple way, production mein cookie ya header use kar)
    response = RedirectResponse(url=f"/me?token={access_token}", status_code=303)
    return response

# ==================== Protected /me Page ====================

@app.get("/me", response_class=HTMLResponse)
async def me_page(
    request: Request,
    token: str = None,  # From query param after login
    current_user: UserOut = Depends(get_current_user)
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        "me.html",
        {"request": request, "user": current_user}
    )

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})
