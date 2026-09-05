from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Dataset(Base):
    __tablename__ = "datasets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    dataset_id: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(100), default="user_upload")
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    versions: Mapped[list["DatasetVersion"]] = relationship(
        back_populates="dataset",
        cascade="all, delete-orphan",
    )


class DatasetVersion(Base):
    __tablename__ = "dataset_versions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    dataset_id: Mapped[int] = mapped_column(
        ForeignKey("datasets.id"),
        nullable=False,
        index=True,
    )

    version: Mapped[int] = mapped_column(Integer, nullable=False)

    file_type: Mapped[str] = mapped_column(String(20))
    file_size: Mapped[int] = mapped_column(Integer)

    # Cryptographic integrity
    sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )

    # Post-quantum digital signature
    signature_algorithm: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    signature: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    public_key: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Provenance information associated with this dataset version
    provenance: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="PROCESSED",
    )

    storage_location: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    dataset: Mapped["Dataset"] = relationship(back_populates="versions")
