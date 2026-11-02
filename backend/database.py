import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Override with the DATABASE_URL environment variable (the test suite
# uses this to run against a throwaway database).
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./cyber_situation_room.db"
)

engine = create_engine(
    DATABASE_URL,
    connect_args=(
        {"check_same_thread": False}
        if DATABASE_URL.startswith("sqlite")
        else {}
    )
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()
