import streamlit as st
from enum import Enum
from datetime import datetime
from sqlalchemy import create_engine, ForeignKey, String, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
import hashlib, os, secrets
from cryptography.fernet import Fernet

engine = create_engine('sqlite:///pwm.db', echo=True)
KEY_FILE = "secret.key"

Session = sessionmaker(bind=engine)
session = Session()

def is_admin_setup():
    admin_count = session.scalar(select(func.count()).select_from(User).where(User.role == "Admin"))
    return admin_count

def get_accounts():
    stmt = select(User)
    with engine.connect() as conn:
        result = conn.execute(stmt)
    return result

def confirm_account(un1, pw1):
    stmt = select(User).where(User.username == un1 and User.password_Hash == hash_password(pw1))
    with engine.connect() as conn:
        result = conn.execute(stmt)
        row = result.first()
    if row is not None and len(row) == 5:
        st.session_state.logged_in = True
        st.session_state.role = row[4]
        st.session_state.email = row[2]
        st.session_state.user = row[1]
        st.session_state.id = row[0]
        st.rerun()
    return False

class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    email: Mapped[str | None]
    password_Hash: Mapped[str] = mapped_column(String(125))
    role: Mapped[str] = mapped_column(String(10))

class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    account: Mapped[str] = mapped_column(String(100))
    password: Mapped[str] = mapped_column(String(125))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    last_updated: Mapped[str] = mapped_column(String, server_default=func.datetime('now'))

def hash_password(password: str) -> str:
    """Generates a secure cryptographic hash using PBKDF2 with a random salt."""
    salt = secrets.token_hex(16)  # Generate a secure 16-byte random salt
    iterations = 600000  # Current OWASP recommended iterations for SHA-256
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
    return f"{iterations}${salt}${key.hex()}"

def encrypt_password(password: str) -> str:
    encrypted_bytes = fernet.encrypt(password.encode('utf-8'))
    encrypted_string = encrypted_bytes.decode('utf-8')
    return encrypted_string

def load_or_create_key():
    """Loads existing key or creates a new one if it doesn't exist."""
    key = ''
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

fernet = load_or_create_key()

#Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)

st.title("Password Manager")

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if not st.session_state.logged_in:

    if is_admin_setup() == 0:
        st.header("Create an Administrative Account")
        with st.container():
            with st.form("Admin Setup"):
                new_user = st.text_input("Enter your User Name", value="")
                new_password = st.text_input("Enter your password", type="password")
                new_email = st.text_input("Enter your Email", value="")
                is_admin = st.checkbox("Is Admin?", value=True)
                submitted = st.form_submit_button("Submit")

            if submitted:
                with Session() as session:
                    user = User(
                    username = new_user,
                    email = new_email,
                    password_Hash = hash_password(new_password),
                    role = 'Admin')
                    session.add(user)
                    session.commit()
                    st.rerun()
    else:
        st.header("Please Login or Create an Account")
        tab_1, tab_2 = st.tabs(['Login','Create an Account'])
        with tab_1:
            with st.container():
                with st.form("Login"):
                    un = st.text_input("Enter your User Name", value="")
                    pw = st.text_input("Enter your password", type="password")
                    login = st.form_submit_button("Submit")
            if login:
                confirm_account(un, pw)

        with tab_2:
            with st.container():
                with st.form("Create An Account"):
                    new_user = st.text_input("Username", placeholder="Choose a unique username")
                    new_email = st.text_input("Email Address", placeholder="e.g., name@example.com")
                    new_password = st.text_input("Password", type="password", placeholder="Enter a strong password")
                    confirm_password = st.text_input("Confirm Password", type="password", placeholder="Re-enter your password")
                    agree = st.checkbox("I agree to the Terms of Service and Privacy Policy")
                    submit_button = st.form_submit_button("Register Account")

                if submit_button:
                    if not new_user or not new_email or not hash_password or not confirm_password:
                        st.error("All fields are required!")
                    elif new_password != confirm_password:
                        st.error("Passwords do not match!")
                    else:
                        with Session() as session:
                            user = User(
                                username=new_user,
                                email=new_email,
                                password_Hash=hash_password(new_password))
                            session.add(user)
                            session.commit()
                            st.rerun()
else:
    st.header("Welcome")

    st.write(f"{st.session_state.id}, {st.session_state.user}, {st.session_state.role}, {st.session_state.email}")
    if st.session_state.role == 'Admin':
        tab_1, tab_2, tab_3 = st.tabs(['Login', 'New', 'Manage Users'])
        with tab_3:
            st.write("Accounts")
            accounts = get_accounts()
            for account in accounts:
                st.write(account[1])

    else:
        tab_1, tab_2 = st.tabs(['Login', 'New'])
    with tab_1:
        st.write(st.session_state.logged_in)
        result = session.execute(select(Account))
        for row in result:
            bytes_to_decrypt = row.Account.password.encode('utf-8')
            decrypted_bytes = fernet.decrypt(bytes_to_decrypt)
            decrypted_message = decrypted_bytes.decode('utf-8')
            st.write(f"Username: {row.Account.account}, Password: {decrypted_message}")


    with tab_2:
        st.write(st.session_state.id)
        with st.container():
            with st.form("New"):
                new_user = st.text_input("Username", placeholder="")
                new_password = st.text_input("Password", type="password")
                submit_button = st.form_submit_button("Register Account")

            if submit_button:
                now = datetime.now()
                with Session() as session:
                    account = Account(
                        account=new_user,
                        password=encrypt_password(new_password),
                        user_id=st.session_state.id,
                        last_updated=now
                    )
                    session.add(account)
                    session.commit()
                    st.rerun()
    if st.button('Log Out'):
        st.session_state["logged_in"] = False
        st.rerun()
