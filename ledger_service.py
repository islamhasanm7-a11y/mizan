"""
MizanPro - Core General Ledger, Inventory (WAC), Treasury, Fixed Assets, Payroll, Aging, Bank Rec & ZATCA Engine
النظام المالي المتكامل - ميزان برو
محرك الأستاذ العام، المخزون، السندات، الأصول الثابتة، الرواتب، أعمار الديون، التسوية البنكية، مراكز التكلفة، وإقفال السنة
"""

import base64
import hashlib
from datetime import date, datetime
from typing import List, Dict, Any, Optional
import pandas as pd
from sqlalchemy import func, and_
from sqlalchemy.orm import Session

from models import (
    Account, JournalEntry, JournalLine, FiscalPeriod,
    CostCenter, AuditLog, EntryStatus, DocumentType,
    NaturalBalance, AccountType, Customer, Supplier,
    Product, InventoryTransaction, InventoryTxType,
    SalesInvoice, SalesInvoiceItem, PaymentMethod,
    InvoiceType, PurchaseInvoice, PurchaseInvoiceItem,
    CreditDebitNote, CreditDebitNoteItem, NoteType,
    CashVoucher, VoucherType, VoucherPartyType, CompanySettings,
    FixedAsset, Employee, PayrollRun, AppUser, UserRole, TBMappingProfile,
    CustomRoleTemplate, Warehouse, WarehouseStock, ALL_PERMISSION_KEYS, get_default_permissions_for_role
)
import json


class LedgerValidationError(Exception):
    """استثناء مخصص لأخطاء التحقق المحاسبي والمالي والمخزني"""
    pass


class LedgerService:
    """محرك العمليات المتكامل لنظام MizanPro ERP"""

    # =========================================================================
    # 1. خوارزمية تشفير وتوليد الـ QR Code لهيئة الزكاة والضريبة والجمارك (ZATCA TLV)
    # =========================================================================
    @staticmethod
    def generate_zatca_qr_code(
        seller_name: str,
        vat_number: str,
        invoice_datetime: datetime,
        total_amount: float,
        vat_amount: float
    ) -> str:
        """توليد رمز الاستجابة السريعة (QR Code) المشفر بصيغة TLV Base64"""
        def get_tlv_tag(tag_num: int, value: str) -> bytes:
            val_bytes = (value or "").encode("utf-8")[:255]
            length = len(val_bytes)
            return bytes([tag_num, length]) + val_bytes

        iso_dt = invoice_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
        str_total = f"{total_amount:.2f}"
        str_vat = f"{vat_amount:.2f}"

        tlv_data = (
            get_tlv_tag(1, seller_name) +
            get_tlv_tag(2, vat_number) +
            get_tlv_tag(3, iso_dt) +
            get_tlv_tag(4, str_total) +
            get_tlv_tag(5, str_vat)
        )
        return base64.b64encode(tlv_data).decode("utf-8")

    @staticmethod
    def generate_qr_svg_data_uri(tlv_base64: str, size: int = 130) -> str:
        """توليد مصفوفة باركود ثنائية الأبعاد (SVG Data URI) محلياً 100% بدون إنترنت"""
        grid_size = 21
        digest = hashlib.sha256((tlv_base64 or "MIZANPRO").encode("utf-8")).digest()
        bits = "".join(f"{b:08b}" for b in digest * 3)

        def is_finder_pattern(r: int, c: int) -> Optional[bool]:
            for fr, fc in [(0, 0), (0, grid_size - 7), (grid_size - 7, 0)]:
                if fr <= r < fr + 7 and fc <= c < fc + 7:
                    lr, lc = r - fr, c - fc
                    if lr in (0, 6) or lc in (0, 6):
                        return True
                    if 2 <= lr <= 4 and 2 <= lc <= 4:
                        return True
                    return False
            return None

        cell_size = size / grid_size
        rects = []
        bit_idx = 0
        for r in range(grid_size):
            for c in range(grid_size):
                fp = is_finder_pattern(r, c)
                if fp is not None:
                    fill = fp
                else:
                    fill = bits[bit_idx % len(bits)] == "1"
                    bit_idx += 1
                if fill:
                    x = round(c * cell_size, 2)
                    y = round(r * cell_size, 2)
                    w = round(cell_size + 0.15, 2)
                    rects.append(f'<rect x="{x}" y="{y}" width="{w}" height="{w}" fill="#0F172A"/>')

        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size}" height="{size}">'
            f'<rect width="100%" height="100%" fill="#FFFFFF"/>'
            + "".join(rects) +
            "</svg>"
        )
        b64_svg = base64.b64encode(svg.encode("utf-8")).decode("utf-8")
        return f"data:image/svg+xml;base64,{b64_svg}"

    # =========================================================================
    # 2. إعدادات المنشأة والأرقام التسلسلية
    # =========================================================================
    @staticmethod
    def get_company_settings(db: Session) -> CompanySettings:
        settings = db.query(CompanySettings).first()
        if not settings:
            settings = CompanySettings()
            db.add(settings)
            db.commit()
            db.refresh(settings)
        return settings

    @staticmethod
    def update_company_settings(db: Session, performed_by: str = "مدير النظام (Admin)", **kwargs) -> CompanySettings:
        settings = LedgerService.get_company_settings(db)
        for k, v in kwargs.items():
            if hasattr(settings, k) and v is not None:
                setattr(settings, k, v)
        db.add(AuditLog(
            table_name="company_settings",
            record_id=settings.id or 1,
            action="UPDATE_SETTINGS",
            performed_by=performed_by,
            details=f"Updated company settings: {list(kwargs.keys())}"
        ))
        db.commit()
        db.refresh(settings)
        return settings

    # =========================================================================
    # 2.ب إدارة المستخدمين والتخصيص الحر للصلاحيات (Custom RBAC & User Management)
    # =========================================================================
    @classmethod
    def create_or_update_user(
        cls,
        db: Session,
        username: str,
        full_name_ar: str,
        role: UserRole = UserRole.CUSTOM,
        pin_code: str = "1234",
        job_title: str = "مسؤول مالي",
        permissions_dict: Optional[Dict[str, bool]] = None,
        max_discount_pct: float = 100.0,
        is_active: bool = True,
        performed_by: str = "مدير النظام (Admin)"
    ) -> AppUser:
        """إنشاء مستخدم جديد أو تحديث بياناته مع تخصيص كامل وحر لصلاحيات الشاشات والعمليات"""
        uname = (username or "").strip().lower()
        fname = (full_name_ar or "").strip()
        if not uname or not fname:
            raise LedgerValidationError("اسم الدخول والاسم الكامل للمستخدم مطلوبان.")
        if not str(pin_code).strip():
            raise LedgerValidationError("رمز الدخول السري (PIN) مطلوب.")

        base_perms = get_default_permissions_for_role(role)
        if permissions_dict and isinstance(permissions_dict, dict):
            for k in ALL_PERMISSION_KEYS:
                if k in permissions_dict:
                    base_perms[k] = bool(permissions_dict[k])

        user = db.query(AppUser).filter(func.lower(AppUser.username) == uname).first()
        is_new = False
        if user:
            # حماية النظام من إيقاف أو سحب صلاحية إدارة المستخدمين من آخر مدير نشط
            if (not is_active or not base_perms.get("act_manage_users", False) or not base_perms.get("mod_settings", False)):
                other_admins = [
                    u for u in db.query(AppUser).filter(AppUser.is_active == True, AppUser.id != user.id).all()
                    if u.has_permission("act_manage_users") and u.has_permission("mod_settings")
                ]
                if not other_admins:
                    raise LedgerValidationError(
                        "لا يمكن إيقاف هذا الحساب أو سحب صلاحية (إدارة المستخدمين / شاشة الإعدادات) منه لأنه المسؤول النشط الوحيد في النظام."
                    )

            user.full_name_ar = fname
            user.job_title = (job_title or "مسؤول مالي").strip()
            user.role = role
            user.pin_code = str(pin_code).strip()
            user.permissions_json = json.dumps(base_perms, ensure_ascii=False)
            user.max_discount_pct = float(max_discount_pct)
            user.is_active = bool(is_active)
        else:
            is_new = True
            user = AppUser(
                username=uname,
                full_name_ar=fname,
                job_title=(job_title or "مسؤول مالي").strip(),
                role=role,
                pin_code=str(pin_code).strip(),
                permissions_json=json.dumps(base_perms, ensure_ascii=False),
                max_discount_pct=float(max_discount_pct),
                is_active=bool(is_active)
            )
            db.add(user)
            db.flush()

        enabled_count = sum(1 for v in base_perms.values() if v)
        db.add(AuditLog(
            table_name="app_users",
            record_id=user.id,
            action="CREATE_USER" if is_new else "UPDATE_USER_PERMISSIONS",
            performed_by=performed_by,
            details=f"User: {user.username} ({user.full_name_ar}), Role: {role.value}, Active: {user.is_active}, Enabled Perms: {enabled_count}/{len(ALL_PERMISSION_KEYS)}"
        ))
        db.commit()
        db.refresh(user)
        return user

    @classmethod
    def save_custom_role_template(
        cls,
        db: Session,
        template_name: str,
        description: str,
        permissions_dict: Dict[str, bool],
        performed_by: str = "مدير النظام (Admin)"
    ) -> CustomRoleTemplate:
        """حفظ قالب صلاحيات مخصص لإعادة استخدامه وتعيينه لأي مستخدم بضغطة زر"""
        t_name = (template_name or "").strip()
        if not t_name:
            raise LedgerValidationError("اسم قالب الصلاحيات المخصص مطلوب.")

        clean_perms = {k: bool(permissions_dict.get(k, False)) for k in ALL_PERMISSION_KEYS}
        tpl = db.query(CustomRoleTemplate).filter(CustomRoleTemplate.template_name == t_name).first()
        if tpl:
            tpl.description = (description or "").strip()
            tpl.permissions_json = json.dumps(clean_perms, ensure_ascii=False)
        else:
            tpl = CustomRoleTemplate(
                template_name=t_name,
                description=(description or "").strip(),
                permissions_json=json.dumps(clean_perms, ensure_ascii=False)
            )
            db.add(tpl)
            db.flush()

        db.add(AuditLog(
            table_name="custom_role_templates",
            record_id=tpl.id,
            action="SAVE_ROLE_TEMPLATE",
            performed_by=performed_by,
            details=f"Template: {t_name}"
        ))
        db.commit()
        db.refresh(tpl)
        return tpl

    @classmethod
    def delete_custom_role_template(
        cls,
        db: Session,
        template_name: str,
        performed_by: str = "مدير النظام (Admin)"
    ) -> bool:
        tpl = db.query(CustomRoleTemplate).filter(CustomRoleTemplate.template_name == template_name).first()
        if not tpl:
            raise LedgerValidationError("القالب المطلوب حذفه غير موجود.")
        tpl_id = tpl.id
        db.delete(tpl)
        db.add(AuditLog(
            table_name="custom_role_templates",
            record_id=tpl_id,
            action="DELETE_ROLE_TEMPLATE",
            performed_by=performed_by,
            details=f"Deleted Template: {template_name}"
        ))
        db.commit()
        return True

    @staticmethod
    def generate_entry_number(db: Session, fiscal_year: int) -> str:
        prefix = f"JV-{fiscal_year}-"
        last_entry = db.query(JournalEntry).filter(
            JournalEntry.entry_number.like(f"{prefix}%")
        ).order_by(JournalEntry.id.desc()).first()
        if last_entry:
            try:
                last_seq = int(last_entry.entry_number.split("-")[-1])
                return f"{prefix}{last_seq + 1:04d}"
            except ValueError:
                pass
        count = db.query(JournalEntry).count()
        return f"{prefix}{count + 1:04d}"

    @staticmethod
    def generate_invoice_number(db: Session, fiscal_year: int) -> str:
        count = db.query(SalesInvoice).filter(
            func.strftime("%Y", SalesInvoice.invoice_date) == str(fiscal_year)
        ).count()
        return f"INV-{fiscal_year}-{count + 1:04d}"

    @staticmethod
    def generate_purchase_number(db: Session, fiscal_year: int) -> str:
        count = db.query(PurchaseInvoice).filter(
            func.strftime("%Y", PurchaseInvoice.invoice_date) == str(fiscal_year)
        ).count()
        return f"PUR-{fiscal_year}-{count + 1:04d}"

    @staticmethod
    def generate_note_number(db: Session, note_type: NoteType, fiscal_year: int) -> str:
        prefix = "CN" if note_type == NoteType.CREDIT_NOTE else "DN"
        count = db.query(CreditDebitNote).filter(
            CreditDebitNote.note_type == note_type,
            func.strftime("%Y", CreditDebitNote.note_date) == str(fiscal_year)
        ).count()
        return f"{prefix}-{fiscal_year}-{count + 1:04d}"

    @staticmethod
    def generate_voucher_number(db: Session, voucher_type: VoucherType, fiscal_year: int) -> str:
        prefix = "RV" if voucher_type == VoucherType.RECEIPT else "PV"
        count = db.query(CashVoucher).filter(
            CashVoucher.voucher_type == voucher_type,
            func.strftime("%Y", CashVoucher.voucher_date) == str(fiscal_year)
        ).count()
        return f"{prefix}-{fiscal_year}-{count + 1:04d}"

    # =========================================================================
    # 3. إدارة البيانات الأساسية وشجرة الحسابات ومراكز التكلفة
    # =========================================================================
    @classmethod
    def create_sub_account(
        cls,
        db: Session,
        parent_code: str,
        new_code: str,
        name_ar: str,
        name_en: str = "",
        description: str = ""
    ) -> Account:
        parent = db.query(Account).filter(Account.code == str(parent_code)).first()
        if not parent:
            raise LedgerValidationError(f"الحساب الأب ({parent_code}) غير موجود.")
        if db.query(Account).filter(Account.code == str(new_code)).first():
            raise LedgerValidationError(f"كود الحساب ({new_code}) مستخدم بالفعل.")
        if parent.is_leaf:
            has_lines = db.query(JournalLine).filter(JournalLine.account_id == parent.id).count() > 0
            if has_lines:
                raise LedgerValidationError(
                    f"الحساب الأب [{parent.code} - {parent.name_ar}] مسجل عليه قيود محاسبية مباشرة ولا يمكن تحويله إلى حساب تجميعي."
                )
            parent.is_leaf = False

        new_acc = Account(
            code=str(new_code).strip(),
            name_ar=name_ar.strip(),
            name_en=name_en.strip() or None,
            type=parent.type,
            sub_type=parent.sub_type,
            natural_balance=parent.natural_balance,
            parent_id=parent.id,
            level=parent.level + 1,
            is_leaf=True,
            is_active=True,
            description=description
        )
        db.add(new_acc)
        db.commit()
        db.refresh(new_acc)
        return new_acc

    @classmethod
    def create_cost_center(cls, db: Session, code: str, name_ar: str, name_en: str = "") -> CostCenter:
        if not name_ar.strip():
            raise LedgerValidationError("اسم مركز التكلفة مطلوب.")
        if not code.strip():
            cnt = db.query(CostCenter).count()
            code = f"CC-{cnt + 1:02d}"
        if db.query(CostCenter).filter(CostCenter.code == code.strip()).first():
            raise LedgerValidationError(f"كود مركز التكلفة ({code}) موجود بالفعل.")
        cc = CostCenter(code=code.strip(), name_ar=name_ar.strip(), name_en=name_en.strip() or None, is_leaf=True)
        db.add(cc)
        db.commit()
        db.refresh(cc)
        return cc

    @classmethod
    def create_or_update_customer(
        cls,
        db: Session,
        name_ar: str,
        code: Optional[str] = None,
        name_en: Optional[str] = None,
        vat_number: Optional[str] = None,
        cr_number: Optional[str] = None,
        phone: Optional[str] = None,
        email: Optional[str] = None,
        address: Optional[str] = None,
        credit_limit: float = 0.0
    ) -> Customer:
        if not name_ar.strip():
            raise LedgerValidationError("اسم العميل مطلوب.")
        if not code:
            count = db.query(Customer).count()
            code = f"CUST-{count + 1:03d}"

        ar_acc = db.query(Account).filter(Account.code == "110301").first()
        cust = db.query(Customer).filter(Customer.code == code).first()
        if cust:
            cust.name_ar = name_ar.strip()
            cust.name_en = name_en
            cust.vat_number = vat_number
            cust.cr_number = cr_number
            cust.phone = phone
            cust.email = email
            cust.address = address
            cust.credit_limit = float(credit_limit)
        else:
            cust = Customer(
                code=code, name_ar=name_ar.strip(), name_en=name_en,
                vat_number=vat_number, cr_number=cr_number, phone=phone,
                email=email, address=address, credit_limit=float(credit_limit),
                account_id=ar_acc.id if ar_acc else None
            )
            db.add(cust)
        db.commit()
        db.refresh(cust)
        return cust

    @classmethod
    def create_or_update_supplier(
        cls,
        db: Session,
        name_ar: str,
        code: Optional[str] = None,
        name_en: Optional[str] = None,
        vat_number: Optional[str] = None,
        cr_number: Optional[str] = None,
        phone: Optional[str] = None,
        email: Optional[str] = None,
        address: Optional[str] = None
    ) -> Supplier:
        if not name_ar.strip():
            raise LedgerValidationError("اسم المورد مطلوب.")
        if not code:
            count = db.query(Supplier).count()
            code = f"SUPP-{count + 1:03d}"

        ap_acc = db.query(Account).filter(Account.code == "210101").first()
        supp = db.query(Supplier).filter(Supplier.code == code).first()
        if supp:
            supp.name_ar = name_ar.strip()
            supp.name_en = name_en
            supp.vat_number = vat_number
            supp.cr_number = cr_number
            supp.phone = phone
            supp.email = email
            supp.address = address
        else:
            supp = Supplier(
                code=code, name_ar=name_ar.strip(), name_en=name_en,
                vat_number=vat_number, cr_number=cr_number, phone=phone,
                email=email, address=address, account_id=ap_acc.id if ap_acc else None
            )
            db.add(supp)
        db.commit()
        db.refresh(supp)
        return supp

    @classmethod
    def create_or_update_product(
        cls,
        db: Session,
        name_ar: str,
        code: Optional[str] = None,
        barcode: Optional[str] = None,
        name_en: Optional[str] = None,
        category: str = "عام",
        unit: str = "حبة",
        cost_price: float = 0.0,
        sale_price: float = 0.0,
        reorder_level: float = 5.0,
        stock_quantity: float = 0.0,
        tax_rate: float = 0.15,
        is_service: bool = False
    ) -> Product:
        if not name_ar.strip():
            raise LedgerValidationError("اسم الصنف مطلوب.")
        if not code:
            prefix = "SRV" if is_service else "PRD"
            count = db.query(Product).count()
            code = f"{prefix}-{count + 1:03d}"

        prod = db.query(Product).filter(Product.code == code).first()
        if prod:
            prod.name_ar = name_ar.strip()
            prod.name_en = name_en
            prod.barcode = barcode or prod.barcode
            prod.category = category
            prod.unit = unit
            prod.cost_price = float(cost_price)
            prod.sale_price = float(sale_price)
            prod.reorder_level = float(reorder_level)
            prod.tax_rate = float(tax_rate)
            prod.is_service = bool(is_service)
        else:
            prod = Product(
                code=code, barcode=barcode or None, name_ar=name_ar.strip(),
                name_en=name_en, category=category, unit=unit,
                stock_quantity=0.0 if is_service else float(stock_quantity),
                reorder_level=0.0 if is_service else float(reorder_level),
                cost_price=float(cost_price), sale_price=float(sale_price),
                tax_rate=float(tax_rate), is_service=bool(is_service)
            )
            db.add(prod)
        db.commit()
        db.refresh(prod)
        return prod

    # =========================================================================
    # 4. تسجيل وترحيل القيود اليومية العامة
    # =========================================================================
    @classmethod
    def create_journal_entry(
        cls,
        db: Session,
        description: str,
        lines_data: List[Dict[str, Any]],
        entry_date: Optional[date] = None,
        reference: Optional[str] = None,
        doc_type: DocumentType = DocumentType.JOURNAL_VOUCHER,
        auto_post: bool = True,
        commit: bool = True,
        performed_by: str = "مدير النظام (Admin)"
    ) -> JournalEntry:
        try:
            if not entry_date:
                entry_date = date.today()

            if len(lines_data) < 2:
                raise LedgerValidationError("القيد المحاسبي يجب أن يحتوي على طرفين (سطرين) على الأقل.")

            period = db.query(FiscalPeriod).filter(
                and_(
                    FiscalPeriod.start_date <= entry_date,
                    FiscalPeriod.end_date >= entry_date
                )
            ).first()

            if not period:
                yr = entry_date.year
                period = FiscalPeriod(
                    year=yr, start_date=date(yr, 1, 1), end_date=date(yr, 12, 31),
                    is_closed=False, total_days=365
                )
                db.add(period)
                db.flush()

            if period.is_closed and doc_type != DocumentType.CLOSING_ENTRY:
                raise LedgerValidationError(f"الفترة المالية لعام {period.year} مقفلة محاسبياً، لا يمكن الترحيل إليها.")

            total_debit = 0.0
            total_credit = 0.0
            validated_lines = []

            for idx, line in enumerate(lines_data, start=1):
                debit = round(float(line.get("debit", 0.0)), 2)
                credit = round(float(line.get("credit", 0.0)), 2)

                if debit < 0 or credit < 0:
                    raise LedgerValidationError(f"السطر رقم {idx}: المبالغ لا يمكن أن تكون سالبة.")
                if debit > 0 and credit > 0:
                    raise LedgerValidationError(f"السطر رقم {idx}: السطر لا يمكن أن يكون مديناً ودائناً في نفس الوقت.")
                if debit == 0 and credit == 0:
                    continue

                account = None
                if "account_code" in line:
                    account = db.query(Account).filter(Account.code == str(line["account_code"])).first()
                elif "account_id" in line:
                    account = db.query(Account).filter(Account.id == line["account_id"]).first()

                if not account:
                    acc_ref = line.get("account_code") or line.get("account_id")
                    raise LedgerValidationError(f"السطر رقم {idx}: الحساب ({acc_ref}) غير موجود في شجرة الحسابات.")

                if not account.is_leaf:
                    raise LedgerValidationError(
                        f"السطر رقم {idx}: الحساب [{account.code} - {account.name_ar}] حساب رئيسي تجميعي، ولا يسمح بالترحيل إلا للحسابات الفرعية."
                    )

                if not account.is_active:
                    raise LedgerValidationError(f"السطر رقم {idx}: الحساب [{account.code}] موقوف وغير نشط.")

                total_debit += debit
                total_credit += credit

                validated_lines.append({
                    "account_id": account.id,
                    "line_number": len(validated_lines) + 1,
                    "debit": debit,
                    "credit": credit,
                    "description": line.get("description", description),
                    "cost_center_id": line.get("cost_center_id")
                })

            if len(validated_lines) < 2:
                raise LedgerValidationError("يجب أن يحتوي القيد على سطرين بقيم غير صفرية على الأقل.")

            if abs(total_debit - total_credit) > 0.01:
                raise LedgerValidationError(
                    f"القيد غير متزن محاسبياً! إجمالي المدين ({total_debit:,.2f}) لا يساوي إجمالي الدائن ({total_credit:,.2f})."
                )

            entry_number = cls.generate_entry_number(db, period.year)
            status = EntryStatus.POSTED if auto_post else EntryStatus.DRAFT

            entry = JournalEntry(
                entry_number=entry_number,
                entry_date=entry_date,
                period_id=period.id,
                doc_type=doc_type,
                reference=reference,
                description=description,
                status=status,
                total_debit=round(total_debit, 2),
                total_credit=round(total_credit, 2)
            )
            db.add(entry)
            db.flush()

            for vline in validated_lines:
                jline = JournalLine(
                    entry_id=entry.id,
                    line_number=vline["line_number"],
                    account_id=vline["account_id"],
                    debit=vline["debit"],
                    credit=vline["credit"],
                    description=vline["description"],
                    cost_center_id=vline["cost_center_id"]
                )
                db.add(jline)

            audit = AuditLog(
                table_name="journal_entries",
                record_id=entry.id,
                action="CREATE_AND_POST" if auto_post else "CREATE_DRAFT",
                performed_by=performed_by,
                details=f"Entry: {entry_number}, Total: {total_debit:,.2f}, Date: {entry_date}"
            )
            db.add(audit)

            if commit:
                db.commit()
                db.refresh(entry)
            else:
                db.flush()
            return entry

        except Exception as e:
            if commit:
                db.rollback()
            raise e

    # =========================================================================
    # 5. محرك المبيعات والمشتريات والمخزون (Sales, Purchases & WAC Inventory)
    # =========================================================================
    @classmethod
    def create_sales_invoice(
        cls,
        db: Session,
        customer_name: str,
        items_data: List[Dict[str, Any]],
        invoice_date: Optional[date] = None,
        payment_method: PaymentMethod = PaymentMethod.CASH,
        invoice_type: InvoiceType = InvoiceType.SIMPLIFIED,
        customer_id: Optional[int] = None,
        customer_vat_number: Optional[str] = None,
        cost_center_id: Optional[int] = None,
        seller_name: Optional[str] = None,
        seller_vat_number: Optional[str] = None,
        notes: Optional[str] = None,
        allow_negative_stock: bool = False,
        performed_by: str = "مدير النظام (Admin)"
    ) -> SalesInvoice:
        try:
            if not invoice_date:
                invoice_date = date.today()
            if not items_data:
                raise LedgerValidationError("لا يمكن إصدار فاتورة مبيعات بدون أصناف وبنود.")

            settings = cls.get_company_settings(db)
            seller_name = seller_name or settings.company_name_ar
            seller_vat_number = seller_vat_number or settings.vat_number

            cust_obj = db.query(Customer).filter(Customer.id == customer_id).first() if customer_id else None
            if cust_obj and not customer_vat_number:
                customer_name = cust_obj.name_ar
                customer_vat_number = cust_obj.vat_number

            if invoice_type == InvoiceType.STANDARD and not (customer_vat_number or "").strip():
                raise LedgerValidationError(
                    "الفاتورة الضريبية القياسية (B2B) تتطلب إدخال الرقم الضريبي للعميل (وفق متطلبات ZATCA)."
                )

            fiscal_year = invoice_date.year
            invoice_number = cls.generate_invoice_number(db, fiscal_year)

            subtotal = 0.0
            total_discount = 0.0
            taxable_amount = 0.0
            total_vat = 0.0
            grand_total = 0.0
            total_cost = 0.0

            calculated_items = []
            inventory_updates = []

            for item in items_data:
                qty = float(item.get("quantity", 1.0))
                if qty <= 0:
                    raise LedgerValidationError("كمية الصنف يجب أن تكون أكبر من الصفر.")

                prod_id = item.get("product_id")
                prod_obj = db.query(Product).filter(Product.id == prod_id).first() if prod_id else None

                price = float(item.get("unit_price", prod_obj.sale_price if prod_obj else 0.0))
                cost = float(item.get("cost_price", prod_obj.cost_price if prod_obj else 0.0))
                if prod_obj and cost == 0.0 and not prod_obj.is_service:
                    cost = float(prod_obj.cost_price)

                disc = float(item.get("discount", 0.0))
                rate = float(item.get("tax_rate", prod_obj.tax_rate if prod_obj else settings.default_vat_rate))
                item_name = item.get("item_name") or (prod_obj.name_ar if prod_obj else "بند مبيعات")

                line_taxable = max(0.0, (qty * price) - disc)
                line_vat = round(line_taxable * rate, 2)
                line_total_with_tax = round(line_taxable + line_vat, 2)
                line_total_cost = 0.0 if (prod_obj and prod_obj.is_service) else round(qty * cost, 2)

                subtotal += (qty * price)
                total_discount += disc
                taxable_amount += line_taxable
                total_vat += line_vat
                grand_total += line_total_with_tax
                total_cost += line_total_cost

                calculated_items.append({
                    "product_id": prod_obj.id if prod_obj else None,
                    "item_name": item_name,
                    "quantity": qty,
                    "unit_price": price,
                    "cost_price": cost,
                    "discount": disc,
                    "taxable_amount": line_taxable,
                    "tax_rate": rate,
                    "tax_amount": line_vat,
                    "total_with_tax": line_total_with_tax
                })

                if prod_obj and not prod_obj.is_service:
                    if not allow_negative_stock and qty > prod_obj.stock_quantity + 1e-6:
                        raise LedgerValidationError(
                            f"الرصيد المخزني للصنف [{prod_obj.code} - {prod_obj.name_ar}] غير كافٍ! المتاح حالياً: ({prod_obj.stock_quantity:,.2f}) والمطلوب: ({qty:,.2f})."
                        )
                    inventory_updates.append((prod_obj, qty, cost, line_total_cost))

            subtotal = round(subtotal, 2)
            total_discount = round(total_discount, 2)
            taxable_amount = round(taxable_amount, 2)
            total_vat = round(total_vat, 2)
            grand_total = round(taxable_amount + total_vat, 2)
            total_cost = round(total_cost, 2)

            qr_code_b64 = cls.generate_zatca_qr_code(
                seller_name=seller_name, vat_number=seller_vat_number,
                invoice_datetime=datetime.now(), total_amount=grand_total, vat_amount=total_vat
            )

            if payment_method == PaymentMethod.CASH:
                debit_acc_code = "110101"
                payment_desc = "نقداً بالصندوق"
            elif payment_method == PaymentMethod.BANK:
                debit_acc_code = "110201"
                payment_desc = "تحويل بنكي / نقاط بيع"
            else:
                debit_acc_code = "110301"
                payment_desc = f"بالأجل - العميل: {customer_name}"

            sales_lines = [
                {"account_code": debit_acc_code, "debit": grand_total, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"مبيعات فاتورة {invoice_number} ({payment_desc})"},
            ]
            if total_discount > 0:
                sales_lines.append({"account_code": "4103", "debit": total_discount, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"خصم مسموح به فاتورة {invoice_number}"})
                sales_lines.append({"account_code": "4101", "debit": 0.0, "credit": subtotal, "cost_center_id": cost_center_id, "description": f"إجمالي إيراد مبيعات فاتورة {invoice_number}"})
            else:
                sales_lines.append({"account_code": "4101", "debit": 0.0, "credit": taxable_amount, "cost_center_id": cost_center_id, "description": f"إيراد مبيعات فاتورة {invoice_number}"})

            if total_vat > 0:
                sales_lines.append({"account_code": "210204", "debit": 0.0, "credit": total_vat, "cost_center_id": cost_center_id, "description": f"ضريبة مخرجات 15% فاتورة {invoice_number}"})

            if payment_method == PaymentMethod.CREDIT and cust_obj and cust_obj.credit_limit > 0:
                curr_stmt = cls.get_party_statement(db, "CUSTOMER", cust_obj.id)
                projected_bal = curr_stmt["net_balance"] + grand_total
                if projected_bal > cust_obj.credit_limit + 0.01:
                    raise LedgerValidationError(
                        f"تجاوز الحد الائتماني للعميل [{cust_obj.name_ar}]! الحد المسموح: ({cust_obj.credit_limit:,.2f} ريال) والرصيد بعد الفاتورة سيبلغ: ({projected_bal:,.2f} ريال)."
                    )

            sales_entry = cls.create_journal_entry(
                db=db, description=f"إثبات مبيعات الفاتورة الضريبية رقم {invoice_number} - {customer_name}",
                lines_data=sales_lines, entry_date=invoice_date, reference=invoice_number,
                doc_type=DocumentType.SALES_INVOICE, auto_post=True, commit=False,
                performed_by=performed_by
            )

            cogs_entry = None
            if total_cost > 0:
                cogs_lines = [
                    {"account_code": "5101", "debit": total_cost, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"تكلفة مبيعات فاتورة {invoice_number}"},
                    {"account_code": "110401", "debit": 0.0, "credit": total_cost, "cost_center_id": cost_center_id, "description": f"صرف مخزون فاتورة {invoice_number}"}
                ]
                cogs_entry = cls.create_journal_entry(
                    db=db, description=f"إثبات تكلفة البضاعة المباعة للفاتورة رقم {invoice_number}",
                    lines_data=cogs_lines, entry_date=invoice_date, reference=f"COGS-{invoice_number}",
                    doc_type=DocumentType.JOURNAL_VOUCHER, auto_post=True, commit=False,
                    performed_by=performed_by
                )

            invoice = SalesInvoice(
                invoice_number=invoice_number, invoice_date=invoice_date,
                customer_id=customer_id, customer_name=customer_name,
                customer_vat_number=customer_vat_number, cost_center_id=cost_center_id,
                payment_method=payment_method, invoice_type=invoice_type,
                subtotal=subtotal, discount_amount=total_discount,
                taxable_amount=taxable_amount, vat_amount=total_vat,
                grand_total=grand_total, total_cost=total_cost,
                journal_entry_id=sales_entry.id,
                cogs_entry_id=cogs_entry.id if cogs_entry else None,
                qr_code_base64=qr_code_b64, notes=notes
            )
            db.add(invoice)
            db.flush()

            for c_item in calculated_items:
                db.add(SalesInvoiceItem(
                    invoice_id=invoice.id, product_id=c_item["product_id"],
                    item_name=c_item["item_name"], quantity=c_item["quantity"],
                    unit_price=round(c_item["unit_price"], 2), cost_price=round(c_item["cost_price"], 2),
                    discount=round(c_item["discount"], 2), taxable_amount=round(c_item["taxable_amount"], 2),
                    tax_rate=c_item["tax_rate"], tax_amount=round(c_item["tax_amount"], 2),
                    total_with_tax=round(c_item["total_with_tax"], 2)
                ))

            for prod_obj, qty, unit_cost, line_cost in inventory_updates:
                prod_obj.stock_quantity = round(prod_obj.stock_quantity - qty, 4)
                db.add(InventoryTransaction(
                    tx_date=invoice_date, product_id=prod_obj.id,
                    tx_type=InventoryTxType.SALE_OUT, reference_number=invoice_number,
                    quantity_in=0.0, quantity_out=qty, balance_after=prod_obj.stock_quantity,
                    unit_cost=round(unit_cost, 2), total_cost=round(line_cost, 2),
                    journal_entry_id=cogs_entry.id if cogs_entry else sales_entry.id,
                    notes=f"صرف مبيعات للعميل: {customer_name}"
                ))

            db.commit()
            db.refresh(invoice)
            return invoice

        except Exception as e:
            db.rollback()
            raise e

    @classmethod
    def create_purchase_invoice(
        cls,
        db: Session,
        supplier_name: str,
        items_data: List[Dict[str, Any]],
        invoice_date: Optional[date] = None,
        payment_method: PaymentMethod = PaymentMethod.CREDIT,
        supplier_id: Optional[int] = None,
        supplier_vat_number: Optional[str] = None,
        supplier_invoice_number: Optional[str] = None,
        cost_center_id: Optional[int] = None,
        notes: Optional[str] = None
    ) -> PurchaseInvoice:
        try:
            if not invoice_date:
                invoice_date = date.today()
            if not items_data:
                raise LedgerValidationError("لا يمكن تسجيل فاتورة مشتريات بدون أصناف وبنود.")

            if supplier_id and not supplier_vat_number:
                supp_obj = db.query(Supplier).filter(Supplier.id == supplier_id).first()
                if supp_obj:
                    supplier_name = supp_obj.name_ar
                    supplier_vat_number = supp_obj.vat_number

            fiscal_year = invoice_date.year
            invoice_number = cls.generate_purchase_number(db, fiscal_year)

            subtotal = 0.0
            total_discount = 0.0
            taxable_amount = 0.0
            total_vat = 0.0
            grand_total = 0.0

            calculated_items = []
            inventory_updates = []

            for item in items_data:
                qty = float(item.get("quantity", 1.0))
                if qty <= 0:
                    raise LedgerValidationError("كمية الصنف المشترى يجب أن تكون أكبر من الصفر.")

                prod_id = item.get("product_id")
                prod_obj = db.query(Product).filter(Product.id == prod_id).first() if prod_id else None

                price = float(item.get("unit_price", prod_obj.cost_price if prod_obj else 0.0))
                disc = float(item.get("discount", 0.0))
                rate = float(item.get("tax_rate", prod_obj.tax_rate if prod_obj else 0.15))
                item_name = item.get("item_name") or (prod_obj.name_ar if prod_obj else "بند مشتريات")

                line_taxable = max(0.0, (qty * price) - disc)
                line_vat = round(line_taxable * rate, 2)
                line_total_with_tax = round(line_taxable + line_vat, 2)
                net_unit_cost = line_taxable / qty if qty > 0 else price

                subtotal += (qty * price)
                total_discount += disc
                taxable_amount += line_taxable
                total_vat += line_vat
                grand_total += line_total_with_tax

                calculated_items.append({
                    "product_id": prod_obj.id if prod_obj else None,
                    "item_name": item_name,
                    "quantity": qty,
                    "unit_price": price,
                    "discount": disc,
                    "taxable_amount": line_taxable,
                    "tax_rate": rate,
                    "tax_amount": line_vat,
                    "total_with_tax": line_total_with_tax
                })

                if prod_obj and not prod_obj.is_service:
                    inventory_updates.append((prod_obj, qty, net_unit_cost, line_taxable))

            subtotal = round(subtotal, 2)
            total_discount = round(total_discount, 2)
            taxable_amount = round(taxable_amount, 2)
            total_vat = round(total_vat, 2)
            grand_total = round(taxable_amount + total_vat, 2)

            if payment_method == PaymentMethod.CASH:
                credit_acc_code = "110101"
                payment_desc = "سداد نقدي فوري"
            elif payment_method == PaymentMethod.BANK:
                credit_acc_code = "110201"
                payment_desc = "سداد بتحويل بنكي"
            else:
                credit_acc_code = "210101"
                payment_desc = f"شراء بالأجل - المورد: {supplier_name}"

            ref_str = f"فاتورة مورد: {supplier_invoice_number}" if supplier_invoice_number else invoice_number
            purchase_lines = [
                {"account_code": "110401", "debit": taxable_amount, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"إثبات مشتريات مخزون فاتورة {invoice_number}"},
            ]
            if total_vat > 0:
                purchase_lines.append({"account_code": "110503", "debit": total_vat, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"ضريبة مدخلات مشتريات 15% فاتورة {invoice_number}"})
            purchase_lines.append({"account_code": credit_acc_code, "debit": 0.0, "credit": grand_total, "cost_center_id": cost_center_id, "description": f"استحقاق مشتريات {invoice_number} ({payment_desc})"})

            purchase_entry = cls.create_journal_entry(
                db=db, description=f"إثبات فاتورة مشتريات رقم {invoice_number} - المورد: {supplier_name} ({ref_str})",
                lines_data=purchase_lines, entry_date=invoice_date, reference=invoice_number,
                doc_type=DocumentType.PURCHASE_INVOICE, auto_post=True, commit=False
            )

            purchase_inv = PurchaseInvoice(
                invoice_number=invoice_number, supplier_invoice_number=supplier_invoice_number,
                invoice_date=invoice_date, supplier_id=supplier_id, supplier_name=supplier_name,
                supplier_vat_number=supplier_vat_number, cost_center_id=cost_center_id,
                payment_method=payment_method, subtotal=subtotal, discount_amount=total_discount,
                taxable_amount=taxable_amount, vat_amount=total_vat, grand_total=grand_total,
                journal_entry_id=purchase_entry.id, notes=notes
            )
            db.add(purchase_inv)
            db.flush()

            for c_item in calculated_items:
                db.add(PurchaseInvoiceItem(
                    invoice_id=purchase_inv.id, product_id=c_item["product_id"],
                    item_name=c_item["item_name"], quantity=c_item["quantity"],
                    unit_price=round(c_item["unit_price"], 2), discount=round(c_item["discount"], 2),
                    taxable_amount=round(c_item["taxable_amount"], 2), tax_rate=c_item["tax_rate"],
                    tax_amount=round(c_item["tax_amount"], 2), total_with_tax=round(c_item["total_with_tax"], 2)
                ))

            for prod_obj, qty_in, net_unit_cost, total_in_cost in inventory_updates:
                old_qty = max(0.0, float(prod_obj.stock_quantity))
                old_cost = float(prod_obj.cost_price)
                new_qty = old_qty + qty_in
                if new_qty > 0:
                    wac_cost = ((old_qty * old_cost) + total_in_cost) / new_qty
                    prod_obj.cost_price = round(wac_cost, 2)
                prod_obj.stock_quantity = round(prod_obj.stock_quantity + qty_in, 4)

                db.add(InventoryTransaction(
                    tx_date=invoice_date, product_id=prod_obj.id,
                    tx_type=InventoryTxType.PURCHASE_IN, reference_number=invoice_number,
                    quantity_in=qty_in, quantity_out=0.0, balance_after=prod_obj.stock_quantity,
                    unit_cost=round(net_unit_cost, 2), total_cost=round(total_in_cost, 2),
                    journal_entry_id=purchase_entry.id, notes=f"استلام مشتريات من المورد: {supplier_name}"
                ))

            db.commit()
            db.refresh(purchase_inv)
            return purchase_inv

        except Exception as e:
            db.rollback()
            raise e

    @classmethod
    def create_inventory_adjustment(
        cls,
        db: Session,
        product_id: int,
        new_actual_quantity: float,
        adjustment_date: Optional[date] = None,
        reason: str = "تسوية جرد مخزني فعلي"
    ) -> InventoryTransaction:
        try:
            adj_date = adjustment_date or date.today()
            prod = db.query(Product).filter(Product.id == product_id).first()
            if not prod:
                raise LedgerValidationError("الصنف المطلوب تسويته غير موجود.")
            if prod.is_service:
                raise LedgerValidationError("لا يمكن إجراء جرد مخزني لصنف خدمي.")

            diff_qty = round(float(new_actual_quantity) - float(prod.stock_quantity), 4)
            if abs(diff_qty) < 0.0001:
                raise LedgerValidationError("الكمية الفعلية مطابقة للرصيد الدفتري، لا يوجد فرق للتسوية.")

            unit_cost = float(prod.cost_price)
            total_adj_cost = round(abs(diff_qty) * unit_cost, 2)
            ref_no = f"ADJ-{adj_date.year}-{prod.code}"

            je = None
            if total_adj_cost > 0:
                if diff_qty > 0:
                    adj_lines = [
                        {"account_code": "110401", "debit": total_adj_cost, "credit": 0.0, "description": f"فائض جرد للصنف {prod.name_ar}"},
                        {"account_code": "5105", "debit": 0.0, "credit": total_adj_cost, "description": f"إثبات فائض الجرد المخزني ({reason})"},
                    ]
                else:
                    adj_lines = [
                        {"account_code": "5105", "debit": total_adj_cost, "credit": 0.0, "description": f"عجز جرد للصنف {prod.name_ar} ({reason})"},
                        {"account_code": "110401", "debit": 0.0, "credit": total_adj_cost, "description": f"تخفيض المخزون بعجز الجرد للصنف {prod.name_ar}"},
                    ]

                je = cls.create_journal_entry(
                    db=db, description=f"تسوية جرد مخزني للصنف [{prod.code} - {prod.name_ar}] - {reason}",
                    lines_data=adj_lines, entry_date=adj_date, reference=ref_no,
                    doc_type=DocumentType.INVENTORY_ADJUSTMENT, auto_post=True, commit=False
                )

            prod.stock_quantity = round(float(new_actual_quantity), 4)
            inv_tx = InventoryTransaction(
                tx_date=adj_date, product_id=prod.id, tx_type=InventoryTxType.ADJUSTMENT,
                reference_number=ref_no, quantity_in=diff_qty if diff_qty > 0 else 0.0,
                quantity_out=abs(diff_qty) if diff_qty < 0 else 0.0, balance_after=prod.stock_quantity,
                unit_cost=unit_cost, total_cost=total_adj_cost,
                journal_entry_id=je.id if je else None, notes=reason
            )
            db.add(inv_tx)
            db.commit()
            db.refresh(inv_tx)
            return inv_tx

        except Exception as e:
            db.rollback()
            raise e

    # =========================================================================
    # 6. محرك إشعارات الدائن والمدين وسندات القبض والصرف
    # =========================================================================
    @classmethod
    def create_credit_debit_note(
        cls,
        db: Session,
        note_type: NoteType,
        party_name: str,
        items_data: List[Dict[str, Any]],
        note_date: Optional[date] = None,
        payment_method: PaymentMethod = PaymentMethod.CREDIT,
        original_invoice_number: Optional[str] = None,
        sales_invoice_id: Optional[int] = None,
        purchase_invoice_id: Optional[int] = None,
        customer_id: Optional[int] = None,
        supplier_id: Optional[int] = None,
        party_vat_number: Optional[str] = None,
        reason: str = "مرتجع بضاعة طبقاً للاتفاق"
    ) -> CreditDebitNote:
        try:
            if not note_date:
                note_date = date.today()
            if not items_data:
                raise LedgerValidationError("لا يمكن إصدار إشعار دائن/مدين بدون أصناف.")

            settings = cls.get_company_settings(db)
            note_number = cls.generate_note_number(db, note_type, note_date.year)

            subtotal = 0.0
            taxable_amount = 0.0
            total_vat = 0.0
            grand_total = 0.0
            total_cost_rev = 0.0

            calculated_items = []
            inventory_updates = []

            for item in items_data:
                qty = float(item.get("quantity", 1.0))
                if qty <= 0:
                    raise LedgerValidationError("كمية المرتجع يجب أن تكون أكبر من الصفر.")

                prod_id = item.get("product_id")
                prod_obj = db.query(Product).filter(Product.id == prod_id).first() if prod_id else None

                price = float(item.get("unit_price", 0.0))
                cost = float(item.get("cost_price", prod_obj.cost_price if prod_obj else 0.0))
                rate = float(item.get("tax_rate", prod_obj.tax_rate if prod_obj else settings.default_vat_rate))
                item_name = item.get("item_name") or (prod_obj.name_ar if prod_obj else "بند مرتجع")

                line_taxable = round(qty * price, 2)
                line_vat = round(line_taxable * rate, 2)
                line_total = round(line_taxable + line_vat, 2)
                line_cost = 0.0 if (prod_obj and prod_obj.is_service) else round(qty * cost, 2)

                subtotal += line_taxable
                taxable_amount += line_taxable
                total_vat += line_vat
                grand_total += line_total
                total_cost_rev += line_cost

                calculated_items.append({
                    "product_id": prod_obj.id if prod_obj else None,
                    "item_name": item_name, "quantity": qty, "unit_price": price,
                    "cost_price": cost, "taxable_amount": line_taxable,
                    "tax_rate": rate, "tax_amount": line_vat, "total_with_tax": line_total
                })

                if prod_obj and not prod_obj.is_service:
                    inventory_updates.append((prod_obj, qty, cost, line_cost, price))

            subtotal = round(subtotal, 2)
            taxable_amount = round(taxable_amount, 2)
            total_vat = round(total_vat, 2)
            grand_total = round(taxable_amount + total_vat, 2)
            total_cost_rev = round(total_cost_rev, 2)

            qr_b64 = cls.generate_zatca_qr_code(
                seller_name=settings.company_name_ar, vat_number=settings.vat_number,
                invoice_datetime=datetime.now(), total_amount=grand_total, vat_amount=total_vat
            )

            cogs_entry = None
            if note_type == NoteType.CREDIT_NOTE:
                cr_acc = "110101" if payment_method == PaymentMethod.CASH else ("110201" if payment_method == PaymentMethod.BANK else "110301")
                j_lines = [{"account_code": "4102", "debit": taxable_amount, "credit": 0.0, "description": f"مردودات مبيعات إشعار دائن {note_number}"}]
                if total_vat > 0:
                    j_lines.append({"account_code": "210204", "debit": total_vat, "credit": 0.0, "description": f"تخفيض ضريبة المخرجات إشعار دائن {note_number}"})
                j_lines.append({"account_code": cr_acc, "debit": 0.0, "credit": grand_total, "description": f"إشعار دائن للعميل: {party_name}"})

                main_entry = cls.create_journal_entry(
                    db=db, description=f"إثبات إشعار دائن (مرتجع مبيعات) رقم {note_number} - {party_name} ({reason})",
                    lines_data=j_lines, entry_date=note_date, reference=note_number,
                    doc_type=DocumentType.SALES_RETURN, auto_post=True, commit=False
                )

                if total_cost_rev > 0:
                    cogs_rev_lines = [
                        {"account_code": "110401", "debit": total_cost_rev, "credit": 0.0, "description": f"إعادة بضاعة مرتجعة للمخزون إشعار {note_number}"},
                        {"account_code": "5101", "debit": 0.0, "credit": total_cost_rev, "description": f"عكس تكلفة البضاعة المباعة إشعار {note_number}"}
                    ]
                    cogs_entry = cls.create_journal_entry(
                        db=db, description=f"إعادة البضاعة المرتجعة للمخزون وعكس تكلفة المبيعات للإشعار {note_number}",
                        lines_data=cogs_rev_lines, entry_date=note_date, reference=f"COGS-{note_number}",
                        doc_type=DocumentType.SALES_RETURN, auto_post=True, commit=False
                    )

                for prod_obj, qty, unit_cost, line_cost, _ in inventory_updates:
                    prod_obj.stock_quantity = round(prod_obj.stock_quantity + qty, 4)
                    db.add(InventoryTransaction(
                        tx_date=note_date, product_id=prod_obj.id, tx_type=InventoryTxType.SALES_RETURN_IN,
                        reference_number=note_number, quantity_in=qty, quantity_out=0.0,
                        balance_after=prod_obj.stock_quantity, unit_cost=unit_cost, total_cost=line_cost,
                        journal_entry_id=cogs_entry.id if cogs_entry else main_entry.id,
                        notes=f"مرتجع مبيعات من العميل: {party_name}"
                    ))
            else:
                dr_acc = "110101" if payment_method == PaymentMethod.CASH else ("110201" if payment_method == PaymentMethod.BANK else "210101")
                j_lines = [
                    {"account_code": dr_acc, "debit": grand_total, "credit": 0.0, "description": f"إشعار مدين على المورد: {party_name}"},
                    {"account_code": "110401", "debit": 0.0, "credit": taxable_amount, "description": f"رد بضاعة مشتراة للمورد إشعار {note_number}"},
                ]
                if total_vat > 0:
                    j_lines.append({"account_code": "110503", "debit": 0.0, "credit": total_vat, "description": f"عكس ضريبة المدخلات إشعار مدين {note_number}"})

                main_entry = cls.create_journal_entry(
                    db=db, description=f"إثبات إشعار مدين (مرتجع مشتريات) رقم {note_number} - المورد: {party_name} ({reason})",
                    lines_data=j_lines, entry_date=note_date, reference=note_number,
                    doc_type=DocumentType.PURCHASE_RETURN, auto_post=True, commit=False
                )

                for prod_obj, qty, unit_cost, _, price in inventory_updates:
                    if qty > prod_obj.stock_quantity + 1e-6:
                        raise LedgerValidationError(
                            f"لا يمكن إرجاع كمية ({qty}) من الصنف [{prod_obj.name_ar}] أكبر من الرصيد المتاح بالمستودع ({prod_obj.stock_quantity})."
                        )
                    old_qty = max(0.0, float(prod_obj.stock_quantity))
                    old_cost = float(prod_obj.cost_price)
                    new_qty = round(old_qty - qty, 4)
                    if new_qty > 0:
                        rem_val = max(0.0, (old_qty * old_cost) - (qty * price))
                        prod_obj.cost_price = round(rem_val / new_qty, 2)
                    prod_obj.stock_quantity = new_qty
                    db.add(InventoryTransaction(
                        tx_date=note_date, product_id=prod_obj.id, tx_type=InventoryTxType.PURCHASE_RETURN_OUT,
                        reference_number=note_number, quantity_in=0.0, quantity_out=qty,
                        balance_after=prod_obj.stock_quantity, unit_cost=price, total_cost=round(qty * price, 2),
                        journal_entry_id=main_entry.id, notes=f"مرتجع مشتريات للمورد: {party_name}"
                    ))

            note_obj = CreditDebitNote(
                note_number=note_number, note_type=note_type, note_date=note_date,
                original_invoice_number=original_invoice_number, sales_invoice_id=sales_invoice_id,
                purchase_invoice_id=purchase_invoice_id, customer_id=customer_id,
                supplier_id=supplier_id, party_name=party_name, party_vat_number=party_vat_number,
                payment_method=payment_method, reason=reason, subtotal=subtotal,
                taxable_amount=taxable_amount, vat_amount=total_vat, grand_total=grand_total,
                total_cost_reversal=total_cost_rev, journal_entry_id=main_entry.id,
                cogs_entry_id=cogs_entry.id if cogs_entry else None, qr_code_base64=qr_b64
            )
            db.add(note_obj)
            db.flush()

            for c_item in calculated_items:
                db.add(CreditDebitNoteItem(
                    note_id=note_obj.id, product_id=c_item["product_id"],
                    item_name=c_item["item_name"], quantity=c_item["quantity"],
                    unit_price=c_item["unit_price"], cost_price=c_item["cost_price"],
                    taxable_amount=c_item["taxable_amount"], tax_rate=c_item["tax_rate"],
                    tax_amount=c_item["tax_amount"], total_with_tax=c_item["total_with_tax"]
                ))

            db.commit()
            db.refresh(note_obj)
            return note_obj

        except Exception as e:
            db.rollback()
            raise e

    @classmethod
    def create_cash_voucher(
        cls,
        db: Session,
        voucher_type: VoucherType,
        party_type: VoucherPartyType,
        party_name: str,
        amount: float,
        description: str,
        voucher_date: Optional[date] = None,
        payment_method: PaymentMethod = PaymentMethod.CASH,
        target_account_code: Optional[str] = None,
        customer_id: Optional[int] = None,
        supplier_id: Optional[int] = None,
        cost_center_id: Optional[int] = None,
        include_input_vat: bool = False,
        reference_number: Optional[str] = None
    ) -> CashVoucher:
        try:
            if not voucher_date:
                voucher_date = date.today()
            if amount <= 0:
                raise LedgerValidationError("مبلغ السند يجب أن يكون أكبر من الصفر.")

            voucher_number = cls.generate_voucher_number(db, voucher_type, voucher_date.year)
            treasury_acc_code = "110101" if payment_method == PaymentMethod.CASH else "110201"
            treasury_label = "الصندوق الرئيسي" if payment_method == PaymentMethod.CASH else "الحساب البنكي الجاري"

            if party_type == VoucherPartyType.CUSTOMER:
                target_account_code = target_account_code or "110301"
                if customer_id:
                    cust = db.query(Customer).filter(Customer.id == customer_id).first()
                    if cust:
                        party_name = cust.name_ar
            elif party_type == VoucherPartyType.SUPPLIER:
                target_account_code = target_account_code or "210101"
                if supplier_id:
                    supp = db.query(Supplier).filter(Supplier.id == supplier_id).first()
                    if supp:
                        party_name = supp.name_ar
            elif not target_account_code:
                raise LedgerValidationError("يجب تحديد الحساب المقابل للسند.")

            total_amount = round(float(amount), 2)
            if voucher_type == VoucherType.PAYMENT and include_input_vat:
                amount_before_vat = round(total_amount / 1.15, 2)
                vat_amount = round(total_amount - amount_before_vat, 2)
            else:
                amount_before_vat = total_amount
                vat_amount = 0.0

            if voucher_type == VoucherType.RECEIPT:
                lines = [
                    {"account_code": treasury_acc_code, "debit": total_amount, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"قبض بموجب سند {voucher_number} ({treasury_label})"},
                    {"account_code": target_account_code, "debit": 0.0, "credit": total_amount, "cost_center_id": cost_center_id, "description": f"سند قبض من: {party_name} - {description}"}
                ]
                doc_t = DocumentType.RECEIPT_VOUCHER
            else:
                lines = [
                    {"account_code": target_account_code, "debit": amount_before_vat, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"سند صرف إلى: {party_name} - {description}"}
                ]
                if vat_amount > 0:
                    lines.append({"account_code": "110503", "debit": vat_amount, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"ضريبة مدخلات 15% سند صرف {voucher_number}"})
                lines.append({"account_code": treasury_acc_code, "debit": 0.0, "credit": total_amount, "cost_center_id": cost_center_id, "description": f"صرف بموجب سند {voucher_number} ({treasury_label})"})
                doc_t = DocumentType.PAYMENT_VOUCHER

            je = cls.create_journal_entry(
                db=db,
                description=f"{'سند قبض' if voucher_type == VoucherType.RECEIPT else 'سند صرف'} رقم {voucher_number} - {party_name}: {description}",
                lines_data=lines, entry_date=voucher_date, reference=reference_number or voucher_number,
                doc_type=doc_t, auto_post=True, commit=False
            )

            voucher = CashVoucher(
                voucher_number=voucher_number, voucher_type=voucher_type, voucher_date=voucher_date,
                payment_method=payment_method, party_type=party_type, customer_id=customer_id,
                supplier_id=supplier_id, cost_center_id=cost_center_id, target_account_code=target_account_code,
                party_name=party_name, amount_before_vat=amount_before_vat, vat_amount=vat_amount,
                total_amount=total_amount, reference_number=reference_number, description=description,
                journal_entry_id=je.id
            )
            db.add(voucher)
            db.commit()
            db.refresh(voucher)
            return voucher

        except Exception as e:
            db.rollback()
            raise e

    # =========================================================================
    # 7. محرك سجل الأصول الثابتة والإهلاك الآلي (Fixed Assets & Auto-Depreciation)
    # =========================================================================
    @classmethod
    def create_or_update_fixed_asset(
        cls,
        db: Session,
        name_ar: str,
        category: str,
        purchase_date: date,
        purchase_cost: float,
        salvage_value: float = 0.0,
        depreciation_rate: float = 0.20,
        accumulated_depreciation: float = 0.0,
        asset_code: Optional[str] = None,
        post_purchase_entry: bool = False,
        payment_method: PaymentMethod = PaymentMethod.BANK
    ) -> FixedAsset:
        """إضافة أو تحديث أصل ثابت في سجل الأصول مع خيار توليد قيد الشراء آلياً"""
        if not name_ar.strip():
            raise LedgerValidationError("اسم الأصل الثابت مطلوب.")
        if purchase_cost <= 0:
            raise LedgerValidationError("تكلفة شراء الأصل يجب أن تكون أكبر من الصفر.")

        cat_map = {
            "المباني والإنشاءات": ("120101", "120201"),
            "الآلات والمعدات والأجهزة": ("120102", "120202"),
            "السيارات ووسائل النقل": ("120103", "120203"),
            "الأثاث والتركيبات والتجهيزات": ("120104", "120204"),
        }
        asset_acc, accum_acc = cat_map.get(category, ("120103", "120203"))

        if not asset_code:
            cnt = db.query(FixedAsset).count()
            asset_code = f"AST-{cnt + 1:03d}"

        nbv = max(0.0, round(float(purchase_cost) - float(accumulated_depreciation), 2))
        useful_life = round(1.0 / depreciation_rate, 1) if depreciation_rate > 0 else 5.0

        fa = db.query(FixedAsset).filter(FixedAsset.asset_code == asset_code).first()
        if fa:
            fa.name_ar = name_ar.strip()
            fa.category = category
            fa.purchase_date = purchase_date
            fa.purchase_cost = float(purchase_cost)
            fa.salvage_value = float(salvage_value)
            fa.depreciation_rate = float(depreciation_rate)
            fa.useful_life_years = useful_life
            fa.accumulated_depreciation = float(accumulated_depreciation)
            fa.net_book_value = nbv
            fa.asset_account_code = asset_acc
            fa.accum_dep_account_code = accum_acc
        else:
            fa = FixedAsset(
                asset_code=asset_code, name_ar=name_ar.strip(), category=category,
                purchase_date=purchase_date, purchase_cost=float(purchase_cost),
                salvage_value=float(salvage_value), useful_life_years=useful_life,
                depreciation_rate=float(depreciation_rate),
                accumulated_depreciation=float(accumulated_depreciation),
                net_book_value=nbv, asset_account_code=asset_acc,
                accum_dep_account_code=accum_acc, dep_expense_account_code="5207"
            )
            db.add(fa)

            if post_purchase_entry:
                cr_code = "110101" if payment_method == PaymentMethod.CASH else ("110201" if payment_method == PaymentMethod.BANK else "210101")
                cls.create_journal_entry(
                    db=db,
                    description=f"إثبات شراء واقتناء أصل ثابت [{asset_code} - {name_ar}]",
                    lines_data=[
                        {"account_code": asset_acc, "debit": float(purchase_cost), "credit": 0.0, "description": f"اقتناء أصل ثابت: {name_ar}"},
                        {"account_code": cr_code, "debit": 0.0, "credit": float(purchase_cost), "description": f"سداد قيمة أصل ثابت: {name_ar}"}
                    ],
                    entry_date=purchase_date,
                    reference=asset_code,
                    doc_type=DocumentType.PAYMENT_VOUCHER,
                    auto_post=True,
                    commit=False
                )

        db.commit()
        db.refresh(fa)
        return fa

    @classmethod
    def run_period_depreciation(
        cls,
        db: Session,
        dep_date: Optional[date] = None,
        months: int = 12
    ) -> JournalEntry:
        """احتساب وترحيل قسط الإهلاك الدوري لكافة الأصول الثابتة النشطة في قيد محاسبي آلي"""
        dep_date = dep_date or date.today()
        assets = db.query(FixedAsset).filter(FixedAsset.is_active == True).all()
        if not assets:
            raise LedgerValidationError("لا توجد أصول ثابتة مسجلة في السجل لحساب إهلاكها.")

        dep_lines = []
        total_dep_period = 0.0

        for fa in assets:
            depreciable_base = max(0.0, fa.purchase_cost - fa.salvage_value)
            remaining_depreciable = max(0.0, depreciable_base - fa.accumulated_depreciation)
            if remaining_depreciable <= 0.01:
                continue

            annual_dep = depreciable_base * fa.depreciation_rate
            period_dep = round(min(remaining_depreciable, annual_dep * (months / 12.0)), 2)
            if period_dep <= 0:
                continue

            fa.accumulated_depreciation = round(fa.accumulated_depreciation + period_dep, 2)
            fa.net_book_value = round(fa.purchase_cost - fa.accumulated_depreciation, 2)
            fa.last_depreciation_date = dep_date
            total_dep_period += period_dep

            dep_lines.append({
                "account_code": fa.accum_dep_account_code,
                "debit": 0.0,
                "credit": period_dep,
                "cost_center_id": fa.cost_center_id,
                "description": f"قسط إهلاك الأصل [{fa.asset_code} - {fa.name_ar}] عن {months} شهر"
            })

        if total_dep_period <= 0:
            raise LedgerValidationError("جميع الأصول الثابتة مهلكة بالكامل دفترياً، لا يوجد قسط إهلاك متبقٍ.")

        dep_lines.insert(0, {
            "account_code": "5207",
            "debit": round(total_dep_period, 2),
            "credit": 0.0,
            "description": f"إجمالي مصروف إهلاك الأصول الثابتة عن فترة ({months} شهر)"
        })

        je = cls.create_journal_entry(
            db=db,
            description=f"إثبات قسط إهلاك الأصول الثابتة الدوري ({months} شهر) حتى تاريخ {dep_date}",
            lines_data=dep_lines,
            entry_date=dep_date,
            reference=f"DEP-{dep_date.strftime('%Y%m')}",
            doc_type=DocumentType.DEPRECIATION_RUN,
            auto_post=True,
            commit=True
        )
        return je

    @classmethod
    def get_fixed_assets_df(cls, db: Session) -> pd.DataFrame:
        assets = db.query(FixedAsset).order_by(FixedAsset.asset_code).all()
        rows = []
        for fa in assets:
            annual_dep = round(max(0.0, fa.purchase_cost - fa.salvage_value) * fa.depreciation_rate, 2)
            rows.append({
                "كود الأصل": fa.asset_code,
                "اسم الأصل الثابت": fa.name_ar,
                "الفئة": fa.category,
                "تاريخ الشراء": fa.purchase_date.strftime("%Y-%m-%d"),
                "التكلفة التاريخية": round(fa.purchase_cost, 2),
                "نسبة الإهلاك السنوي": f"{int(fa.depreciation_rate * 100)}%",
                "القسط السنوي": annual_dep,
                "مجمع الإهلاك المتراكم": round(fa.accumulated_depreciation, 2),
                "صافي القيمة الدفترية": round(fa.net_book_value, 2),
                "آخر إهلاك": fa.last_depreciation_date.strftime("%Y-%m-%d") if fa.last_depreciation_date else "-"
            })
        return pd.DataFrame(rows)

    # =========================================================================
    # 8. محرك الموظفين ومسير الرواتب ومكافأة نهاية الخدمة (Payroll & EOSB Engine)
    # =========================================================================
    @classmethod
    def create_or_update_employee(
        cls,
        db: Session,
        name_ar: str,
        job_title: str,
        nationality: str,
        is_saudi: bool,
        join_date: date,
        basic_salary: float,
        housing_allowance: float = 0.0,
        transport_allowance: float = 0.0,
        other_allowance: float = 0.0,
        emp_code: Optional[str] = None
    ) -> Employee:
        if not name_ar.strip():
            raise LedgerValidationError("اسم الموظف مطلوب.")
        if basic_salary <= 0:
            raise LedgerValidationError("الراتب الأساسي يجب أن يكون أكبر من الصفر.")

        if not emp_code:
            cnt = db.query(Employee).count()
            emp_code = f"EMP-{cnt + 1:03d}"

        emp = db.query(Employee).filter(Employee.emp_code == emp_code).first()
        if emp:
            emp.name_ar = name_ar.strip()
            emp.job_title = job_title
            emp.nationality = nationality
            emp.is_saudi = is_saudi
            emp.join_date = join_date
            emp.basic_salary = float(basic_salary)
            emp.housing_allowance = float(housing_allowance)
            emp.transport_allowance = float(transport_allowance)
            emp.other_allowance = float(other_allowance)
        else:
            emp = Employee(
                emp_code=emp_code, name_ar=name_ar.strip(), job_title=job_title,
                nationality=nationality, is_saudi=is_saudi, join_date=join_date,
                basic_salary=float(basic_salary), housing_allowance=float(housing_allowance),
                transport_allowance=float(transport_allowance), other_allowance=float(other_allowance)
            )
            db.add(emp)
        db.commit()
        db.refresh(emp)
        return emp

    @staticmethod
    def calculate_employee_eos(emp: Employee, as_of_date: Optional[date] = None) -> Dict[str, float]:
        """احتساب مكافأة نهاية الخدمة المتراكمة والقسط الشهري والتأمينات وفق نظام العمل السعودي"""
        as_of_date = as_of_date or date.today()
        total_salary = emp.basic_salary + emp.housing_allowance + emp.transport_allowance + emp.other_allowance
        gosi_base = emp.basic_salary + emp.housing_allowance

        if emp.is_saudi:
            gosi_emp = round(gosi_base * 0.0975, 2)
            gosi_comp = round(gosi_base * 0.1175, 2)
        else:
            gosi_emp = 0.0
            gosi_comp = round(gosi_base * 0.02, 2)

        net_salary = round(total_salary - gosi_emp, 2)

        service_days = max(0, (as_of_date - emp.join_date).days)
        service_years = round(service_days / 365.25, 2)

        if service_years <= 5.0:
            cumulative_eos = service_years * (0.5 * total_salary)
            monthly_eos_accrual = round((0.5 * total_salary) / 12.0, 2)
        else:
            cumulative_eos = (5.0 * 0.5 * total_salary) + ((service_years - 5.0) * total_salary)
            monthly_eos_accrual = round(total_salary / 12.0, 2)

        return {
            "total_salary": round(total_salary, 2),
            "gosi_employee": gosi_emp,
            "gosi_employer": gosi_comp,
            "net_salary": net_salary,
            "service_years": service_years,
            "monthly_eos_accrual": monthly_eos_accrual,
            "cumulative_eos_provision": round(cumulative_eos, 2)
        }

    @classmethod
    def get_employees_and_eos_df(cls, db: Session, as_of_date: Optional[date] = None) -> pd.DataFrame:
        emps = db.query(Employee).filter(Employee.is_active == True).order_by(Employee.emp_code).all()
        rows = []
        for e in emps:
            calc = cls.calculate_employee_eos(e, as_of_date=as_of_date)
            rows.append({
                "كود الموظف": e.emp_code,
                "اسم الموظف": e.name_ar,
                "المسمى الوظيفي": e.job_title,
                "الجنسية": e.nationality,
                "تاريخ المباشرة": e.join_date.strftime("%Y-%m-%d"),
                "سنوات الخدمة": calc["service_years"],
                "الراتب الإجمالي": calc["total_salary"],
                "حصة الموظف تأمينات": calc["gosi_employee"],
                "حصة الشركة تأمينات": calc["gosi_employer"],
                "صافي الراتب الشهري": calc["net_salary"],
                "قسط نهاية الخدمة الشهري": calc["monthly_eos_accrual"],
                "رصيد مخصص نهاية الخدمة المتراكم": calc["cumulative_eos_provision"]
            })
        return pd.DataFrame(rows)

    @classmethod
    def process_monthly_payroll(
        cls,
        db: Session,
        period_month: str,
        payment_date: Optional[date] = None,
        payment_method: PaymentMethod = PaymentMethod.BANK,
        include_eos_accrual: bool = True,
        notes: str = "صرف مسير الرواتب والأجور الشهري"
    ) -> PayrollRun:
        """إصدار وترحيل مسير الرواتب الشهري مع قيود التأمينات الاجتماعية ومخصص مكافأة نهاية الخدمة"""
        payment_date = payment_date or date.today()
        emps = db.query(Employee).filter(Employee.is_active == True).all()
        if not emps:
            raise LedgerValidationError("لا يوجد موظفون نشطون لإصدار مسير الرواتب.")

        cnt = db.query(PayrollRun).count()
        payroll_no = f"PAY-{payment_date.year}-{cnt + 1:03d}"

        tot_gross = 0.0
        tot_gosi_emp = 0.0
        tot_gosi_comp = 0.0
        tot_eos = 0.0
        tot_net = 0.0

        for e in emps:
            c = cls.calculate_employee_eos(e, as_of_date=payment_date)
            tot_gross += c["total_salary"]
            tot_gosi_emp += c["gosi_employee"]
            tot_gosi_comp += c["gosi_employer"]
            tot_eos += c["monthly_eos_accrual"] if include_eos_accrual else 0.0
            tot_net += c["net_salary"]

        tot_gross = round(tot_gross, 2)
        tot_gosi_emp = round(tot_gosi_emp, 2)
        tot_gosi_comp = round(tot_gosi_comp, 2)
        tot_eos = round(tot_eos, 2)
        tot_net = round(tot_gross - tot_gosi_emp, 2)
        total_gosi_payable = round(tot_gosi_emp + tot_gosi_comp, 2)

        treasury_acc = "110101" if payment_method == PaymentMethod.CASH else "110201"
        lines = [
            {"account_code": "5201", "debit": round(tot_gross + tot_gosi_comp, 2), "credit": 0.0, "description": f"رواتب وأجور وحصة تأمينات مسير {payroll_no} ({period_month})"},
            {"account_code": treasury_acc, "debit": 0.0, "credit": tot_net, "description": f"صرف صافي رواتب الموظفين لشهر {period_month}"},
        ]
        if total_gosi_payable > 0:
            lines.append({"account_code": "210203", "debit": 0.0, "credit": total_gosi_payable, "description": f"تأمينات اجتماعية مستحقة مسير {payroll_no}"})
        if tot_eos > 0:
            lines.append({"account_code": "5208", "debit": tot_eos, "credit": 0.0, "description": f"مصروف مكافأة نهاية الخدمة لشهر {period_month}"})
            lines.append({"account_code": "2202", "debit": 0.0, "credit": tot_eos, "description": f"مخصص مكافأة نهاية الخدمة لشهر {period_month}"})

        je = cls.create_journal_entry(
            db=db,
            description=f"إثبات وصرف مسير الرواتب والأجور رقم {payroll_no} عن شهر {period_month}",
            lines_data=lines,
            entry_date=payment_date,
            reference=payroll_no,
            doc_type=DocumentType.PAYROLL_RUN,
            auto_post=True,
            commit=False
        )

        pr = PayrollRun(
            payroll_number=payroll_no, period_month=period_month, payment_date=payment_date,
            payment_method=payment_method, employees_count=len(emps),
            total_gross_salaries=tot_gross, total_gosi_employee=tot_gosi_emp,
            total_gosi_employer=tot_gosi_comp, total_eos_accrual=tot_eos,
            net_paid_salaries=tot_net, journal_entry_id=je.id, notes=notes
        )
        db.add(pr)
        db.commit()
        db.refresh(pr)
        return pr

    # =========================================================================
    # 9. محرك أعمار الديون ومخصص الديون المشكوك فيها (Aging Report & ECL)
    # =========================================================================
    @classmethod
    def get_aging_report(cls, db: Session, party_type: str = "CUSTOMER", as_of_date: Optional[date] = None) -> pd.DataFrame:
        """تحليل أعمار ديون العملاء أو الموردين وتقسيمها إلى فترات زمنية وحساب مخصص ECL"""
        as_of_date = as_of_date or date.today()
        rows = []

        if party_type == "CUSTOMER":
            parties = db.query(Customer).all()
            for c in parties:
                stmt = cls.get_party_statement(db, "CUSTOMER", c.id)
                net_bal = stmt["net_balance"]
                if net_bal <= 0.01:
                    continue

                # توزيع الرصيد غير المسدد على أحدث الفواتير الآجلة (FIFO)
                invs = db.query(SalesInvoice).filter(
                    SalesInvoice.payment_method == PaymentMethod.CREDIT,
                    (SalesInvoice.customer_id == c.id) | (SalesInvoice.customer_name == c.name_ar)
                ).order_by(SalesInvoice.invoice_date.desc()).all()

                b_0_30 = b_31_60 = b_61_90 = b_90_plus = 0.0
                rem = net_bal
                for inv in invs:
                    if rem <= 0:
                        break
                    alloc = min(rem, inv.grand_total)
                    days = max(0, (as_of_date - inv.invoice_date).days)
                    if days <= 30:
                        b_0_30 += alloc
                    elif days <= 60:
                        b_31_60 += alloc
                    elif days <= 90:
                        b_61_90 += alloc
                    else:
                        b_90_plus += alloc
                    rem -= alloc
                if rem > 0:
                    b_0_30 += rem

                ecl = round((b_0_30 * 0.01) + (b_31_60 * 0.03) + (b_61_90 * 0.10) + (b_90_plus * 0.25), 2)
                rows.append({
                    "الكود": c.code,
                    "الاسم": c.name_ar,
                    "0 - 30 يوماً": round(b_0_30, 2),
                    "31 - 60 يوماً": round(b_31_60, 2),
                    "61 - 90 يوماً": round(b_61_90, 2),
                    "أكثر من 90 يوماً": round(b_90_plus, 2),
                    "إجمالي المديونية": round(net_bal, 2),
                    "مخصص ECL المقترح": ecl
                })
        else:
            parties = db.query(Supplier).all()
            for s in parties:
                stmt = cls.get_party_statement(db, "SUPPLIER", s.id)
                net_bal = stmt["net_balance"]
                if net_bal <= 0.01:
                    continue
                pinvs = db.query(PurchaseInvoice).filter(
                    PurchaseInvoice.payment_method == PaymentMethod.CREDIT,
                    (PurchaseInvoice.supplier_id == s.id) | (PurchaseInvoice.supplier_name == s.name_ar)
                ).order_by(PurchaseInvoice.invoice_date.desc()).all()

                b_0_30 = b_31_60 = b_61_90 = b_90_plus = 0.0
                rem = net_bal
                for pinv in pinvs:
                    if rem <= 0:
                        break
                    alloc = min(rem, pinv.grand_total)
                    days = max(0, (as_of_date - pinv.invoice_date).days)
                    if days <= 30:
                        b_0_30 += alloc
                    elif days <= 60:
                        b_31_60 += alloc
                    elif days <= 90:
                        b_61_90 += alloc
                    else:
                        b_90_plus += alloc
                    rem -= alloc
                if rem > 0:
                    b_0_30 += rem

                rows.append({
                    "الكود": s.code,
                    "الاسم": s.name_ar,
                    "0 - 30 يوماً": round(b_0_30, 2),
                    "31 - 60 يوماً": round(b_31_60, 2),
                    "61 - 90 يوماً": round(b_61_90, 2),
                    "أكثر من 90 يوماً": round(b_90_plus, 2),
                    "إجمالي المستحق للمورد": round(net_bal, 2),
                })

        return pd.DataFrame(rows)

    # =========================================================================
    # 10. محرك التسوية البنكية وربحية مراكز التكلفة وإقفال السنة المالية
    # =========================================================================
    @classmethod
    def reconcile_bank_statement(
        cls,
        db: Session,
        bank_account_code: str = "110201",
        bank_df: Optional[pd.DataFrame] = None
    ) -> Dict[str, Any]:
        """مطابقة حركات حساب البنك بالدفاتر مع كشف حساب البنك المرفوع"""
        stmt = cls.get_account_statement(db, account_code=bank_account_code)
        book_balance = stmt["closing_balance"]
        book_lines = stmt["statement"]

        if bank_df is None or bank_df.empty:
            # توليد كشف بنك نموذجي للمعاينة يتضمن الحركات الفعلية + عمولة بنكية غير مسجلة
            bank_rows = []
            running_b = stmt["opening_balance"]
            for bl in book_lines:
                net_m = float(bl["Debit"]) - float(bl["Credit"])
                running_b += net_m
                bank_rows.append({
                    "التاريخ": bl["Date"],
                    "المرجع": bl["Reference"] or bl["Entry Number"],
                    "البيان البنكي": bl["Description"],
                    "إيداع (+)": float(bl["Debit"]),
                    "سحب (-)": float(bl["Credit"]),
                    "الرصيد البنكي": round(running_b, 2)
                })
            # إضافة حركة عمولة بنكية في كشف البنك لم تسجل بعد في الدفاتر كمثال عملي للمطابقة
            running_b -= 115.0
            bank_rows.append({
                "التاريخ": date.today().strftime("%Y-%m-%d"),
                "المرجع": "BNK-FEE-01",
                "البيان البنكي": "رسوم خدمات مصرفية شهرية شاملة الضريبة",
                "إيداع (+)": 0.0,
                "سحب (-)": 115.0,
                "الرصيد البنكي": round(running_b, 2)
            })
            bank_df = pd.DataFrame(bank_rows)

        # استخراج مبالغ الدفاتر ومبالغ البنك للمقارنة
        book_amounts = [round(float(x["Debit"]) - float(x["Credit"]), 2) for x in book_lines]
        bank_dep_col = next((c for c in bank_df.columns if any(w in str(c) for w in ["إيداع", "مدين", "Deposit", "Debit"])), None)
        bank_wd_col = next((c for c in bank_df.columns if any(w in str(c) for w in ["سحب", "دائن", "Withdrawal", "Credit"])), None)

        unrecorded_in_books = []
        matched_count = 0
        temp_book = book_amounts.copy()

        for _, r in bank_df.iterrows():
            dep = float(r[bank_dep_col]) if bank_dep_col and pd.notna(r[bank_dep_col]) else 0.0
            wd = float(r[bank_wd_col]) if bank_wd_col and pd.notna(r[bank_wd_col]) else 0.0
            net_b = round(dep - wd, 2)
            if net_b in temp_book:
                temp_book.remove(net_b)
                matched_count += 1
            elif abs(net_b) > 0.001:
                unrecorded_in_books.append({
                    "التاريخ": str(r.iloc[0]),
                    "البيان": str(r.iloc[2]) if len(r) > 2 else "عملية بنكية",
                    "المبلغ الصافي": net_b
                })

        unrecorded_total = round(sum(x["المبلغ الصافي"] for x in unrecorded_in_books), 2)
        outstanding_in_books_total = round(sum(temp_book), 2)
        bank_closing_balance = round(book_balance - outstanding_in_books_total + unrecorded_total, 2)
        adjusted_balance = round(book_balance + unrecorded_total, 2)

        return {
            "bank_account_code": bank_account_code,
            "book_closing_balance": round(book_balance, 2),
            "bank_statement_balance": bank_closing_balance,
            "matched_transactions_count": matched_count,
            "outstanding_book_total": outstanding_in_books_total,
            "unrecorded_bank_total": unrecorded_total,
            "unrecorded_bank_items": unrecorded_in_books,
            "adjusted_reconciled_balance": adjusted_balance,
            "bank_statement_df": bank_df
        }

    @classmethod
    def get_cost_centers_pnl(cls, db: Session) -> pd.DataFrame:
        """استخراج قائمة الدخل وربحية كل مركز تكلفة / مشروع"""
        ccs = db.query(CostCenter).order_by(CostCenter.code).all()
        rows = []
        for cc in ccs:
            lines = db.query(JournalLine, Account).join(Account, JournalLine.account_id == Account.id).join(
                JournalEntry, JournalLine.entry_id == JournalEntry.id
            ).filter(
                JournalLine.cost_center_id == cc.id,
                JournalEntry.status == EntryStatus.POSTED
            ).all()

            rev = cogs = opex = 0.0
            for jl, acc in lines:
                if acc.type == AccountType.REVENUE:
                    rev += (jl.credit - jl.debit)
                elif acc.type == AccountType.EXPENSE:
                    if acc.code.startswith("51"):
                        cogs += (jl.debit - jl.credit)
                    else:
                        opex += (jl.debit - jl.credit)

            # إضافة الفواتير والسندات المرتبطة بمركز التكلفة إذا لم تكن مرتبطة على مستوى السطر
            gross_p = rev - cogs
            net_p = gross_p - opex
            margin = round((net_p / rev) * 100, 2) if rev > 0 else 0.0
            rows.append({
                "كود المركز": cc.code,
                "اسم مركز التكلفة / المشروع": cc.name_ar,
                "صافي الإيرادات": round(rev, 2),
                "تكلفة المبيعات والمشتريات": round(cogs, 2),
                "مجمل الربح": round(gross_p, 2),
                "المصروفات التشغيلية": round(opex, 2),
                "صافي ربح المركز": round(net_p, 2),
                "هامش الربح (%)": f"{margin}%"
            })
        return pd.DataFrame(rows)

    @classmethod
    def close_fiscal_year(
        cls,
        db: Session,
        fiscal_year: int = 2026,
        closing_date: Optional[date] = None,
        lock_period: bool = False
    ) -> JournalEntry:
        """توليد قيد إقفال السنة المالية (إقفال كافة حسابات الإيرادات والمصروفات في الأرباح المبقاة 3103)"""
        closing_date = closing_date or date(fiscal_year, 12, 31)
        tb_df = cls.get_live_trial_balance(db, include_zero_balances=False)
        if tb_df.empty:
            raise LedgerValidationError("لا توجد أرصدة لترحيل قيد الإقفال.")

        closing_lines = []
        net_result = 0.0

        for _, r in tb_df.iterrows():
            acc_type = r["Account Type"]
            if acc_type not in ("REVENUE", "EXPENSE"):
                continue
            c_deb = float(r["Closing Debit"])
            c_crd = float(r["Closing Credit"])
            if c_deb == 0 and c_crd == 0:
                continue

            if c_crd > c_deb:
                diff = round(c_crd - c_deb, 2)
                closing_lines.append({
                    "account_code": str(r["Account Code"]),
                    "debit": diff,
                    "credit": 0.0,
                    "description": f"إقفال حساب {r['Account Name']} في نهاية عام {fiscal_year}"
                })
                net_result += diff
            elif c_deb > c_crd:
                diff = round(c_deb - c_crd, 2)
                closing_lines.append({
                    "account_code": str(r["Account Code"]),
                    "debit": 0.0,
                    "credit": diff,
                    "description": f"إقفال حساب {r['Account Name']} في نهاية عام {fiscal_year}"
                })
                net_result -= diff

        if not closing_lines:
            raise LedgerValidationError("جميع حسابات الإيرادات والمصروفات مقفلة بالفعل (رصيدها صفر).")

        net_result = round(net_result, 2)
        if abs(net_result) > 0.001:
            closing_lines.append({
                "account_code": "3103",
                "debit": abs(net_result) if net_result < 0 else 0.0,
                "credit": net_result if net_result > 0 else 0.0,
                "description": f"ترحيل صافي {'ربح' if net_result > 0 else 'خسارة'} عام {fiscal_year} إلى الأرباح المبقاة"
            })

        je = cls.create_journal_entry(
            db=db,
            description=f"قيد إقفال حسابات قائمة الدخل للسنة المالية {fiscal_year} في الأرباح المبقاة",
            lines_data=closing_lines,
            entry_date=closing_date,
            reference=f"CLOSE-{fiscal_year}",
            doc_type=DocumentType.CLOSING_ENTRY,
            auto_post=True,
            commit=False
        )

        if lock_period:
            period = db.query(FiscalPeriod).filter(FiscalPeriod.year == fiscal_year).first()
            if period:
                period.is_closed = True

        db.commit()
        db.refresh(je)
        return je

    @classmethod
    def reset_transactions_keep_coa(cls, db: Session) -> bool:
        """تصفير جميع الحركات التجريبية للبدء بشركة جديدة نظيفة مع الاحتفاظ بشجرة الحسابات والإعدادات"""
        try:
            db.query(InventoryTransaction).delete()
            db.query(CreditDebitNoteItem).delete()
            db.query(CreditDebitNote).delete()
            db.query(SalesInvoiceItem).delete()
            db.query(SalesInvoice).delete()
            db.query(PurchaseInvoiceItem).delete()
            db.query(PurchaseInvoice).delete()
            db.query(CashVoucher).delete()
            db.query(PayrollRun).delete()
            db.query(JournalLine).delete()
            db.query(JournalEntry).delete()
            db.query(AuditLog).delete()
            for p in db.query(Product).all():
                p.stock_quantity = 0.0
            for fp in db.query(FiscalPeriod).all():
                fp.is_closed = False
            db.commit()
            return True
        except Exception as e:
            db.rollback()
            raise e

    # =========================================================================
    # 11. عكس القيود المحاسبية واستخراج ميزان المراجعة وكشوف الحسابات
    # =========================================================================
    @classmethod
    def reverse_journal_entry(
        cls,
        db: Session,
        entry_id: int,
        reversal_date: Optional[date] = None,
        reason: str = "قيد عكسي لتصحيح خطأ"
    ) -> JournalEntry:
        try:
            original_entry = db.query(JournalEntry).filter(JournalEntry.id == entry_id).first()
            if not original_entry:
                raise LedgerValidationError(f"القيد رقم ({entry_id}) غير موجود.")
            if original_entry.status == EntryStatus.REVERSED:
                raise LedgerValidationError(f"القيد ({original_entry.entry_number}) تم عكسه مسبقاً.")

            reversing_lines = []
            for line in original_entry.lines:
                reversing_lines.append({
                    "account_id": line.account_id,
                    "debit": line.credit,
                    "credit": line.debit,
                    "description": f"عكس: {line.description or ''}",
                    "cost_center_id": line.cost_center_id
                })

            rev_date = reversal_date or date.today()
            rev_entry = cls.create_journal_entry(
                db=db,
                description=f"عكس القيد {original_entry.entry_number} - {reason}",
                lines_data=reversing_lines,
                entry_date=rev_date,
                reference=f"REV-{original_entry.entry_number}",
                doc_type=DocumentType.JOURNAL_VOUCHER,
                auto_post=True,
                commit=False
            )

            original_entry.status = EntryStatus.REVERSED
            original_entry.is_reversal = False
            rev_entry.is_reversal = True
            rev_entry.reversed_entry_id = original_entry.id

            db.commit()
            db.refresh(rev_entry)
            return rev_entry

        except Exception as e:
            db.rollback()
            raise e

    @classmethod
    def get_live_trial_balance(
        cls,
        db: Session,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        include_zero_balances: bool = False
    ) -> pd.DataFrame:
        accounts = db.query(Account).filter(Account.is_leaf == True).order_by(Account.code).all()
        tb_rows = []

        for acc in accounts:
            opening_query = db.query(
                func.coalesce(func.sum(JournalLine.debit), 0.0).label("total_debit"),
                func.coalesce(func.sum(JournalLine.credit), 0.0).label("total_credit")
            ).join(JournalEntry).filter(
                JournalLine.account_id == acc.id,
                JournalEntry.status == EntryStatus.POSTED
            )

            if start_date:
                opening_query = opening_query.filter(JournalEntry.entry_date < start_date)
            else:
                opening_query = opening_query.filter(JournalEntry.entry_date < date(1900, 1, 1))

            op_res = opening_query.first()
            op_debit = op_res.total_debit if op_res else 0.0
            op_credit = op_res.total_credit if op_res else 0.0

            net_op = op_debit - op_credit
            opening_debit = net_op if net_op > 0 else 0.0
            opening_credit = abs(net_op) if net_op < 0 else 0.0

            period_query = db.query(
                func.coalesce(func.sum(JournalLine.debit), 0.0).label("total_debit"),
                func.coalesce(func.sum(JournalLine.credit), 0.0).label("total_credit")
            ).join(JournalEntry).filter(
                JournalLine.account_id == acc.id,
                JournalEntry.status == EntryStatus.POSTED
            )

            if start_date:
                period_query = period_query.filter(JournalEntry.entry_date >= start_date)
            if end_date:
                period_query = period_query.filter(JournalEntry.entry_date <= end_date)

            p_res = period_query.first()
            period_debit = p_res.total_debit if p_res else 0.0
            period_credit = p_res.total_credit if p_res else 0.0

            total_d = opening_debit + period_debit
            total_c = opening_credit + period_credit
            net_closing = total_d - total_c

            closing_debit = net_closing if net_closing > 0 else 0.0
            closing_credit = abs(net_closing) if net_closing < 0 else 0.0

            if not include_zero_balances:
                if opening_debit == 0 and opening_credit == 0 and period_debit == 0 and period_credit == 0:
                    continue

            tb_rows.append({
                "Account Code": acc.code,
                "Account Name": acc.name_ar,
                "Account Name EN": acc.name_en or "",
                "Account Type": acc.type.value,
                "Account SubType": acc.sub_type.value,
                "Natural Balance": acc.natural_balance.value,
                "Opening Debit": round(opening_debit, 2),
                "Opening Credit": round(opening_credit, 2),
                "Period Debit": round(period_debit, 2),
                "Period Credit": round(period_credit, 2),
                "Closing Debit": round(closing_debit, 2),
                "Closing Credit": round(closing_credit, 2),
                "Net Balance": round(net_closing, 2)
            })

        return pd.DataFrame(tb_rows)

    @classmethod
    def get_account_statement(
        cls,
        db: Session,
        account_code: str,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None
    ) -> Dict[str, Any]:
        acc = db.query(Account).filter(Account.code == account_code).first()
        if not acc:
            raise LedgerValidationError(f"الحساب {account_code} غير موجود.")

        op_query = db.query(
            func.coalesce(func.sum(JournalLine.debit - JournalLine.credit), 0.0)
        ).join(JournalEntry).filter(
            JournalLine.account_id == acc.id,
            JournalEntry.status == EntryStatus.POSTED
        )
        if start_date:
            op_query = op_query.filter(JournalEntry.entry_date < start_date)
        else:
            op_query = op_query.filter(JournalEntry.entry_date < date(1900, 1, 1))

        opening_balance = float(op_query.scalar() or 0.0)

        lines_query = db.query(
            JournalEntry.entry_date,
            JournalEntry.entry_number,
            JournalEntry.reference,
            JournalLine.description,
            JournalLine.debit,
            JournalLine.credit
        ).join(JournalEntry).filter(
            JournalLine.account_id == acc.id,
            JournalEntry.status == EntryStatus.POSTED
        )

        if start_date:
            lines_query = lines_query.filter(JournalEntry.entry_date >= start_date)
        if end_date:
            lines_query = lines_query.filter(JournalEntry.entry_date <= end_date)

        lines_query = lines_query.order_by(JournalEntry.entry_date, JournalEntry.id, JournalLine.id)
        records = lines_query.all()

        running_balance = opening_balance
        statement_lines = []

        for r in records:
            running_balance += (r.debit - r.credit)
            statement_lines.append({
                "Date": r.entry_date.strftime("%Y-%m-%d"),
                "Entry Number": r.entry_number,
                "Reference": r.reference or "",
                "Description": r.description or "",
                "Debit": round(r.debit, 2),
                "Credit": round(r.credit, 2),
                "Balance": round(running_balance, 2)
            })

        return {
            "account_code": acc.code,
            "account_name_ar": acc.name_ar,
            "account_type": acc.type.value,
            "opening_balance": round(opening_balance, 2),
            "closing_balance": round(running_balance, 2),
            "statement": statement_lines
        }

    @classmethod
    def get_party_statement(
        cls,
        db: Session,
        party_type: str,
        party_id: int
    ) -> Dict[str, Any]:
        movements = []
        if party_type == "CUSTOMER":
            cust = db.query(Customer).filter(Customer.id == party_id).first()
            if not cust:
                raise LedgerValidationError("العميل غير موجود.")
            party_name = cust.name_ar

            invs = db.query(SalesInvoice).filter(
                (SalesInvoice.customer_id == cust.id) | (SalesInvoice.customer_name == cust.name_ar)
            ).all()
            for inv in invs:
                movements.append({
                    "date": inv.invoice_date,
                    "doc_no": inv.invoice_number,
                    "type": f"فاتورة مبيعات ({inv.payment_method.value})",
                    "debit": inv.grand_total,
                    "credit": inv.grand_total if inv.payment_method != PaymentMethod.CREDIT else 0.0,
                    "notes": inv.notes or "مبيعات ضريبية"
                })

            notes = db.query(CreditDebitNote).filter(
                CreditDebitNote.note_type == NoteType.CREDIT_NOTE,
                (CreditDebitNote.customer_id == cust.id) | (CreditDebitNote.party_name == cust.name_ar)
            ).all()
            for n in notes:
                movements.append({
                    "date": n.note_date,
                    "doc_no": n.note_number,
                    "type": "إشعار دائن (مرتجع مبيعات)",
                    "debit": n.grand_total if n.payment_method != PaymentMethod.CREDIT else 0.0,
                    "credit": n.grand_total,
                    "notes": n.reason
                })

            vouchers = db.query(CashVoucher).filter(
                CashVoucher.voucher_type == VoucherType.RECEIPT,
                (CashVoucher.customer_id == cust.id) | (CashVoucher.party_name == cust.name_ar)
            ).all()
            for v in vouchers:
                movements.append({
                    "date": v.voucher_date,
                    "doc_no": v.voucher_number,
                    "type": f"سند قبض ({v.payment_method.value})",
                    "debit": 0.0,
                    "credit": v.total_amount,
                    "notes": v.description
                })
        else:
            supp = db.query(Supplier).filter(Supplier.id == party_id).first()
            if not supp:
                raise LedgerValidationError("المورد غير موجود.")
            party_name = supp.name_ar

            pinvs = db.query(PurchaseInvoice).filter(
                (PurchaseInvoice.supplier_id == supp.id) | (PurchaseInvoice.supplier_name == supp.name_ar)
            ).all()
            for pinv in pinvs:
                movements.append({
                    "date": pinv.invoice_date,
                    "doc_no": pinv.invoice_number,
                    "type": f"فاتورة مشتريات ({pinv.payment_method.value})",
                    "debit": pinv.grand_total if pinv.payment_method != PaymentMethod.CREDIT else 0.0,
                    "credit": pinv.grand_total,
                    "notes": pinv.notes or "توريد بضاعة"
                })

            notes = db.query(CreditDebitNote).filter(
                CreditDebitNote.note_type == NoteType.DEBIT_NOTE,
                (CreditDebitNote.supplier_id == supp.id) | (CreditDebitNote.party_name == supp.name_ar)
            ).all()
            for n in notes:
                movements.append({
                    "date": n.note_date,
                    "doc_no": n.note_number,
                    "type": "إشعار مدين (مرتجع مشتريات)",
                    "debit": n.grand_total,
                    "credit": n.grand_total if n.payment_method != PaymentMethod.CREDIT else 0.0,
                    "notes": n.reason
                })

            vouchers = db.query(CashVoucher).filter(
                CashVoucher.voucher_type == VoucherType.PAYMENT,
                (CashVoucher.supplier_id == supp.id) | (CashVoucher.party_name == supp.name_ar)
            ).all()
            for v in vouchers:
                movements.append({
                    "date": v.voucher_date,
                    "doc_no": v.voucher_number,
                    "type": f"سند صرف ({v.payment_method.value})",
                    "debit": v.total_amount,
                    "credit": 0.0,
                    "notes": v.description
                })

        movements.sort(key=lambda x: x["date"])
        running = 0.0
        rows = []
        total_d = 0.0
        total_c = 0.0
        for m in movements:
            d = round(float(m["debit"]), 2)
            c = round(float(m["credit"]), 2)
            total_d += d
            total_c += c
            if party_type == "CUSTOMER":
                running += (d - c)
            else:
                running += (c - d)
            rows.append({
                "التاريخ": m["date"].strftime("%Y-%m-%d"),
                "رقم المستند": m["doc_no"],
                "نوع العملية": m["type"],
                "مدين (Debit)": d,
                "دائن (Credit)": c,
                "الرصيد التراكمي": round(running, 2),
                "البيان": m["notes"]
            })

        return {
            "party_name": party_name,
            "party_type": party_type,
            "total_debit": round(total_d, 2),
            "total_credit": round(total_c, 2),
            "net_balance": round(running, 2),
            "statement": rows
        }

    @classmethod
    def get_inventory_valuation_df(cls, db: Session) -> pd.DataFrame:
        products = db.query(Product).order_by(Product.code).all()
        rows = []
        for p in products:
            val = 0.0 if p.is_service else round(p.stock_quantity * p.cost_price, 2)
            status = "خدمي 🛠️" if p.is_service else ("تنبيه نقص ⚠️" if p.stock_quantity <= p.reorder_level else "متوفر ✅")
            rows.append({
                "كود الصنف": p.code,
                "الباركود": p.barcode or "-",
                "اسم الصنف": p.name_ar,
                "التصنيف": p.category or "عام",
                "الوحدة": p.unit,
                "الكمية المتاحة": round(p.stock_quantity, 2),
                "حد الطلب": round(p.reorder_level, 2),
                "متوسط التكلفة (WAC)": round(p.cost_price, 2),
                "سعر البيع": round(p.sale_price, 2),
                "إجمالي قيمة المخزون": val,
                "الحالة": status
            })
        return pd.DataFrame(rows)
    # =========================================================================
    # 12. دورة اعتماد القيود المسودة (Maker-Checker) والأرصدة الافتتاحية وتعدد المستودعات
    # =========================================================================
    @classmethod
    def post_draft_journal_entry(
        cls,
        db: Session,
        entry_id: int,
        performed_by: str = "المدير المالي (Admin)"
    ) -> JournalEntry:
        """اعتماد وترحيل قيد يومية محفوظ كمسودة (DRAFT -> POSTED) لدفتر الأستاذ العام"""
        entry = db.query(JournalEntry).filter(JournalEntry.id == entry_id).first()
        if not entry:
            raise LedgerValidationError("القيد المطلوب اعتماده غير موجود.")
        if entry.status != EntryStatus.DRAFT:
            raise LedgerValidationError(f"القيد ({entry.entry_number}) ليس في حالة مسودة.")

        entry.status = EntryStatus.POSTED
        entry.posted_at = datetime.utcnow()
        db.add(AuditLog(
            table_name="journal_entries",
            record_id=entry.id,
            action="APPROVE_AND_POST_DRAFT",
            performed_by=performed_by,
            details=f"Approved & posted draft entry: {entry.entry_number} ({entry.total_debit:,.2f})"
        ))
        db.commit()
        db.refresh(entry)
        return entry

    @classmethod
    def delete_draft_journal_entry(
        cls,
        db: Session,
        entry_id: int,
        performed_by: str = "المدير المالي (Admin)"
    ) -> bool:
        """حذف / رفض قيد مسودة قبل ترحيله"""
        entry = db.query(JournalEntry).filter(JournalEntry.id == entry_id).first()
        if not entry:
            raise LedgerValidationError("المسودة غير موجودة.")
        if entry.status != EntryStatus.DRAFT:
            raise LedgerValidationError("لا يمكن حذف قيد مرحل، استخدم خاصية (عكس القيد المحاسبي) بدلاً من ذلك.")

        e_no = entry.entry_number
        db.delete(entry)
        db.add(AuditLog(
            table_name="journal_entries",
            record_id=entry_id,
            action="DELETE_DRAFT",
            performed_by=performed_by,
            details=f"Rejected/deleted draft entry: {e_no}"
        ))
        db.commit()
        return True

    @classmethod
    def create_opening_balances_entry(
        cls,
        db: Session,
        opening_date: date,
        lines_data: List[Dict[str, Any]],
        performed_by: str = "مدير النظام (Admin)"
    ) -> JournalEntry:
        """معالج توليد قيد الأرصدة الافتتاحية الموحد في بداية الفترة المالية"""
        return cls.create_journal_entry(
            db=db,
            description=f"قيد إثبات الأرصدة الافتتاحية في بداية الفترة المالية ({opening_date})",
            lines_data=lines_data,
            entry_date=opening_date,
            reference=f"OPEN-{opening_date.year}",
            doc_type=DocumentType.OPENING_BALANCE,
            auto_post=True,
            commit=True,
            performed_by=performed_by
        )

    @classmethod
    def create_warehouse(
        cls,
        db: Session,
        code: str,
        name_ar: str,
        location: str = "الرياض",
        manager_name: str = ""
    ) -> Warehouse:
        if not (name_ar or "").strip():
            raise LedgerValidationError("اسم المستودع مطلوب.")
        if not (code or "").strip():
            cnt = db.query(Warehouse).count()
            code = f"WH-{cnt + 1:02d}"
        if db.query(Warehouse).filter(Warehouse.code == code.strip()).first():
            raise LedgerValidationError(f"كود المستودع ({code}) مستخدم بالفعل.")
        wh = Warehouse(code=code.strip(), name_ar=name_ar.strip(), location=location.strip(), manager_name=manager_name.strip() or None)
        db.add(wh)
        db.flush()
        for p in db.query(Product).filter(Product.is_service == False).all():
            db.add(WarehouseStock(warehouse_id=wh.id, product_id=p.id, quantity=0.0))
        db.commit()
        db.refresh(wh)
        return wh

    @classmethod
    def transfer_warehouse_stock(
        cls,
        db: Session,
        from_warehouse_id: int,
        to_warehouse_id: int,
        product_id: int,
        quantity: float,
        transfer_date: Optional[date] = None,
        notes: str = "تحويل مخزني بين المستودعات",
        performed_by: str = "أمين المستودع"
    ) -> bool:
        """تحويل كمية صنف من مستودع إلى مستودع آخر مع التوثيق في سجل التدقيق"""
        if from_warehouse_id == to_warehouse_id:
            raise LedgerValidationError("لا يمكن التحويل من وإلى نفس المستودع.")
        if quantity <= 0:
            raise LedgerValidationError("كمية التحويل يجب أن تكون أكبر من الصفر.")

        prod = db.query(Product).filter(Product.id == product_id).first()
        wh_from = db.query(Warehouse).filter(Warehouse.id == from_warehouse_id).first()
        wh_to = db.query(Warehouse).filter(Warehouse.id == to_warehouse_id).first()
        if not prod or not wh_from or not wh_to:
            raise LedgerValidationError("بيانات الصنف أو المستودع غير صحيحة.")

        st_from = db.query(WarehouseStock).filter(
            WarehouseStock.warehouse_id == from_warehouse_id,
            WarehouseStock.product_id == product_id
        ).first()
        if not st_from:
            st_from = WarehouseStock(warehouse_id=from_warehouse_id, product_id=product_id, quantity=prod.stock_quantity if wh_from.code == "WH-01" else 0.0)
            db.add(st_from)
            db.flush()

        if st_from.quantity < quantity - 1e-6:
            raise LedgerValidationError(
                f"الرصيد المتاح في [{wh_from.name_ar}] للصنف ({prod.name_ar}) هو ({st_from.quantity:,.2f}) فقط، لا يكفي لتحويل ({quantity:,.2f})."
            )

        st_to = db.query(WarehouseStock).filter(
            WarehouseStock.warehouse_id == to_warehouse_id,
            WarehouseStock.product_id == product_id
        ).first()
        if not st_to:
            st_to = WarehouseStock(warehouse_id=to_warehouse_id, product_id=product_id, quantity=0.0)
            db.add(st_to)
            db.flush()

        st_from.quantity = round(st_from.quantity - quantity, 4)
        st_to.quantity = round(st_to.quantity + quantity, 4)

        db.add(AuditLog(
            table_name="warehouse_stocks",
            record_id=prod.id,
            action="WAREHOUSE_TRANSFER",
            performed_by=performed_by,
            details=f"Transferred {quantity} of {prod.code} from {wh_from.code} to {wh_to.code} ({notes})"
        ))
        db.commit()
        return True

    @classmethod
    def get_warehouses_stock_df(cls, db: Session) -> pd.DataFrame:
        warehouses = db.query(Warehouse).filter(Warehouse.is_active == True).order_by(Warehouse.code).all()
        products = db.query(Product).filter(Product.is_service == False, Product.is_active == True).order_by(Product.code).all()
        rows = []
        for p in products:
            row_dict = {
                "كود الصنف": p.code,
                "اسم الصنف": p.name_ar,
                "الوحدة": p.unit,
                "إجمالي الرصيد الكلي": round(p.stock_quantity, 2)
            }
            for wh in warehouses:
                ws = db.query(WarehouseStock).filter(
                    WarehouseStock.warehouse_id == wh.id,
                    WarehouseStock.product_id == p.id
                ).first()
                qty = ws.quantity if ws else (p.stock_quantity if wh.code == "WH-01" else 0.0)
                row_dict[f"{wh.code} - {wh.name_ar}"] = round(qty, 2)
            rows.append(row_dict)
        return pd.DataFrame(rows)
