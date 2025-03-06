"""
Cache database module.
"""

from collections import namedtuple

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Knowledgebase(Base):
    __tablename__ = 'knowledgebase'
    id: Mapped[str] = mapped_column(primary_key=True)
    cves: Mapped[list[str]] = mapped_column(sa.JSON, default=[])
    severity: Mapped[str] = mapped_column(sa.JSON)


def init_db(uri: str = 'sqlite:///cache.db'):
    """
    Initialize the database
    """
    Database = namedtuple('DB', ['engine', 'session'])
    engine = sa.create_engine(uri)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Database(engine=engine, session=Session)
