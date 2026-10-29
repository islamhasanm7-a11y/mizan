"""
MizanPro - Database Engine & Session Management
النظام المالي المتكامل - ميزان برو
ملف إدارة الاتصال بقاعدة البيانات والجلسات
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# مسار قاعدة البيانات المحلية SQLite
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'mizanpro_ledger.db')}"

# محرك قاعدة البيانات
# تم ضبط check_same_thread لـ False لضمان استقرار العمليات المتزامنة في واجهات الويب
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False  # يمكن تفعيلها (True) لمتابعة استعلامات الـ SQL في شاشة الـ Terminal أثناء التطوير
)

# مصنع الجلسات المحاسبية (Session Factory)
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# الفئة الأساسية لنماذج الجداول (Base Model)
Base = declarative_base()


def get_db():
    """
    دالة مولدة (Generator) لإنشاء جلسة تعامل مع قاعدة البيانات
    وتضمن إغلاقها تلقائياً بعد انتهاء العملية لمنع تسريب الذاكرة (Connection Leaks).
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()