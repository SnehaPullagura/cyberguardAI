from abc import ABC, abstractmethod
from typing import Generic, TypeVar, List, Optional, Any
from sqlalchemy.orm import Session

T = TypeVar("T")


class BaseRepository(ABC, Generic[T]):
    """Abstract Base Repository defining standard data access interface."""

    def __init__(self, model_class: type):
        self.model_class = model_class

    def get_by_id(self, db: Session, id_val: Any) -> Optional[T]:
        return db.query(self.model_class).filter(self.model_class.id == id_val).first()

    def get_all(self, db: Session, skip: int = 0, limit: int = 100) -> List[T]:
        return db.query(self.model_class).offset(skip).limit(limit).all()

    def save(self, db: Session, obj: T) -> T:
        db.add(obj)
        db.commit()
        db.refresh(obj)
        return obj

    def delete(self, db: Session, id_val: Any) -> bool:
        obj = self.get_by_id(db, id_val)
        if obj:
            db.delete(obj)
            db.commit()
            return True
        return False
