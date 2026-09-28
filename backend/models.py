from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Float
)

from database import Base


class CVE(Base):
    __tablename__ = "cves"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    cve_id = Column(
        String,
        unique=True,
        index=True,
        nullable=False
    )

    description = Column(Text)

    cvss_score = Column(Float)

    severity = Column(String)

    published_date = Column(String)

    last_modified = Column(String)

    known_exploited = Column(
        Integer,
        default=0
    )

    kev_date_added = Column(String)

    kev_due_date = Column(String)


class Source(Base):
    __tablename__ = "sources"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    name = Column(
        String,
        nullable=False
    )

    url = Column(String)

    source_type = Column(String)


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    title = Column(
        String,
        nullable=False
    )

    description = Column(Text)

    event_type = Column(String)

    severity = Column(String)

    event_date = Column(String)

    source_id = Column(Integer)

    source_name = Column(String)

    source_url = Column(String)

    external_id = Column(
        String,
        unique=True,
        index=True
    )

    advisory_type = Column(String)