from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), index=True)

    source: Mapped[str] = mapped_column(String(50))
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)

    detected_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    risk_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    verdict: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    vt_detections: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    vt_total_engines: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    signed: Mapped[bool | None] = mapped_column(
        nullable=True,
    )

    pe_info: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    mitre_info: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    ai_explanation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )
