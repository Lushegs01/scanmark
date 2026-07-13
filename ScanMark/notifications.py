"""
ScanMark Notification Engine
=============================
Real-time WhatsApp/Email alerts, weekly PDF reports, and
early-warning notifications when attendance slips.
"""

import os
import io
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# PDF generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph,
    Spacer, Image, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.barcharts import VerticalBarChart

# WhatsApp via Twilio
try:
    from twilio.rest import Client as TwilioClient
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False
    print("[WARN] Twilio not installed. WhatsApp alerts disabled. Install with: pip install twilio")


# ============================================================
# TWILIO / WHATSAPP CONFIGURATION
# ============================================================

TWILIO_SID = os.environ.get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH = os.environ.get('TWILIO_AUTH_TOKEN')
TWILIO_WHATSAPP_FROM = os.environ.get('TWILIO_WHATSAPP_FROM', 'whatsapp:+14155238886')

twilio_client = None
if TWILIO_AVAILABLE and TWILIO_SID and TWILIO_AUTH:
    twilio_client = TwilioClient(TWILIO_SID, TWILIO_AUTH)
    print("[OK] WhatsApp Alerts Active (Twilio)")
else:
    print("[INFO] WhatsApp Alerts Disabled (no Twilio credentials)")

# Thread pool for async notifications
notification_executor = ThreadPoolExecutor(max_workers=3)


# ============================================================
# WHATSAPP ALERTS
# ============================================================

def send_whatsapp_message(to_phone, message_body):
    """
    Send a WhatsApp message via Twilio.
    `to_phone` should be in format: +234XXXXXXXXXX
    Returns True on success, False otherwise.
    """
    if not twilio_client:
        print(f"[SKIP] WhatsApp skipped (no client): {message_body[:50]}...")
        return False

    try:
        msg = twilio_client.messages.create(
            body=message_body,
            from_=TWILIO_WHATSAPP_FROM,
            to=f'whatsapp:{to_phone}'
        )
        print(f"[OK] WhatsApp sent to {to_phone}: SID={msg.sid}")
        return True
    except Exception as e:
        print(f"[ERROR] WhatsApp send failed: {e}")
        return False


def send_attendance_whatsapp(phone, student_name, course_code, course_title, timestamp_str):
    """Send real-time WhatsApp alert when attendance is marked."""
    message = (
        f"✅ *Attendance Confirmed*\n\n"
        f"👤 {student_name}\n"
        f"📚 {course_code} — {course_title}\n"
        f"🕐 {timestamp_str}\n\n"
        f"_ScanMark • FUNAAB_"
    )
    notification_executor.submit(send_whatsapp_message, phone, message)


def send_warning_whatsapp(phone, student_name, course_code, attendance_pct, threshold):
    """Send early-warning WhatsApp when attendance drops below threshold."""
    message = (
        f"⚠️ *Attendance Warning*\n\n"
        f"👤 {student_name}\n"
        f"📚 {course_code}\n"
        f"📊 Your attendance: *{attendance_pct:.0f}%* (required: {threshold}%)\n\n"
        f"Please attend the next class to improve your record.\n\n"
        f"_ScanMark • FUNAAB_"
    )
    notification_executor.submit(send_whatsapp_message, phone, message)


# ============================================================
# PARENT / GUARDIAN NOTIFICATIONS
# ============================================================

def send_parent_attendance_whatsapp(phone, parent_name, student_name, course_code, course_title, timestamp_str):
    """Notify a parent/guardian via WhatsApp that their ward marked attendance."""
    message = (
        f"✅ *Attendance Update*\n\n"
        f"Dear {parent_name},\n"
        f"Your ward *{student_name}* has just attended:\n\n"
        f"📚 {course_code} — {course_title}\n"
        f"🕐 {timestamp_str}\n\n"
        f"_ScanMark • FUNAAB_"
    )
    notification_executor.submit(send_whatsapp_message, phone, message)


def send_parent_warning_whatsapp(phone, parent_name, student_name, course_code, attendance_pct, threshold):
    """Alert a parent/guardian via WhatsApp that their ward's attendance is low."""
    message = (
        f"⚠️ *Parent Alert — Low Attendance*\n\n"
        f"Dear {parent_name},\n"
        f"Your ward *{student_name}*'s attendance for *{course_code}* "
        f"is at *{attendance_pct:.0f}%* (minimum: {threshold}%).\n\n"
        f"Please encourage them to attend upcoming classes.\n\n"
        f"_ScanMark • FUNAAB_"
    )
    notification_executor.submit(send_whatsapp_message, phone, message)


def send_parent_attendance_email(app_instance, mail_func, pref, student_name, course_code, course_title, timestamp_str):
    """Email a parent/guardian when their ward marks attendance."""
    parent_name = pref.parent_name or 'Parent/Guardian'
    subject = f"Attendance Update — {student_name} attended {course_code}"

    text_body = (
        f"Dear {parent_name},\n\n"
        f"This is to inform you that your ward, {student_name}, "
        f"attended {course_code} ({course_title}) on {timestamp_str}.\n\n"
        f"— ScanMark, FUNAAB"
    )

    html_body = f"""
<!DOCTYPE html>
<html><head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#f0f4f0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0"
        style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
        <tr>
          <td style="background:linear-gradient(135deg,#006838 0%,#198754 100%);padding:36px 40px;text-align:center;">
            <p style="margin:0 0 8px;font-size:36px;">👨‍👩‍👧</p>
            <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:800;">Attendance Update</h1>
            <p style="margin:6px 0 0;color:rgba(255,255,255,0.8);font-size:13px;">Your ward attended class</p>
          </td>
        </tr>
        <tr>
          <td style="padding:32px 40px;">
            <p style="font-size:16px;color:#1a1a1a;margin:0 0 8px;font-weight:700;">Dear {parent_name},</p>
            <p style="font-size:14px;color:#555;margin:0 0 20px;line-height:1.6;">
              Your ward <strong>{student_name}</strong> has successfully marked attendance for:
            </p>
            <table width="100%" cellpadding="0" cellspacing="0"
              style="border:1px solid #e2e8e2;border-radius:8px;overflow:hidden;margin-bottom:20px;">
              <tr style="background:#f7faf7;">
                <td style="padding:16px;text-align:center;border-right:1px solid #e2e8e2;">
                  <div style="font-size:18px;font-weight:800;color:#006838;">{course_code}</div>
                  <div style="font-size:11px;color:#999;text-transform:uppercase;letter-spacing:1px;">Course</div>
                </td>
                <td style="padding:16px;text-align:center;">
                  <div style="font-size:14px;font-weight:600;color:#333;">{timestamp_str}</div>
                  <div style="font-size:11px;color:#999;text-transform:uppercase;letter-spacing:1px;">Date & Time</div>
                </td>
              </tr>
            </table>
            <p style="font-size:13px;color:#777;line-height:1.5;">
              <strong>{course_title}</strong>
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 40px;border-top:1px solid #e2e8e2;text-align:center;">
            <p style="margin:0;font-size:12px;color:#999;">
              <strong>Federal University of Agriculture, Abeokuta (FUNAAB)</strong><br/>
              &copy; {datetime.now().year} ScanMark Attendance System
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
    """.strip()

    mail_func(subject, pref.parent_email, text_body, html_body)


# ============================================================
# EARLY WARNING SYSTEM
# ============================================================

DEFAULT_ATTENDANCE_THRESHOLD = 75  # percent


def check_attendance_threshold(student, course, db_session, Attendance_model, ClassSession_model):
    """
    Check if a student's attendance for a given course has dropped
    below the configurable threshold.

    Returns:
        (is_below, attendance_pct, threshold)
    """
    from sqlalchemy import or_
    from models import NotificationPreference

    # Only the course's CURRENT semester counts (legacy unlabelled sessions
    # are treated as current until a new semester is started).
    sessions_q = ClassSession_model.query.filter_by(course_id=course.id)
    current_sem = getattr(course, 'current_semester', None)
    if current_sem:
        sessions_q = sessions_q.filter(or_(
            ClassSession_model.semester == current_sem,
            ClassSession_model.semester.is_(None),
        ))
    session_ids = [s.id for s in sessions_q.with_entities(ClassSession_model.id).all()]
    total_sessions = len(session_ids)
    if total_sessions == 0:
        return False, 100.0, DEFAULT_ATTENDANCE_THRESHOLD

    # Count how many of those sessions this student attended
    attended = Attendance_model.query.filter(
        Attendance_model.student_id == student.id,
        Attendance_model.session_id.in_(session_ids)
    ).count()

    attendance_pct = (attended / total_sessions) * 100

    # Check custom threshold
    pref = NotificationPreference.query.filter_by(user_id=student.id).first()
    threshold = pref.warning_threshold if pref else DEFAULT_ATTENDANCE_THRESHOLD

    is_below = attendance_pct < threshold
    return is_below, attendance_pct, threshold


def process_early_warning(student, course, app_instance, mail_func, Attendance_model, ClassSession_model, db_session):
    """
    Full early-warning pipeline: check threshold → send alerts if needed.
    Called after each attendance mark.  Notifies student AND parent/guardian.
    """
    from models import NotificationPreference

    is_below, pct, threshold = check_attendance_threshold(
        student, course, db_session, Attendance_model, ClassSession_model
    )

    if not is_below:
        return  # All good

    pref = NotificationPreference.query.filter_by(user_id=student.id).first()

    # ── Student alerts ──
    if not pref or pref.email_alerts:
        notification_executor.submit(
            _send_warning_email_task,
            app_instance,
            mail_func,
            student.email,
            student.full_name,
            course.code,
            course.title,
            pct,
            threshold
        )

    if pref and pref.whatsapp_alerts and pref.phone_number:
        send_warning_whatsapp(
            pref.phone_number,
            student.full_name,
            course.code,
            pct,
            threshold
        )

    # ── Parent / Guardian alerts ──
    if pref and pref.notify_parent:
        parent_name = pref.parent_name or 'Parent/Guardian'

        # Email the parent
        if pref.parent_email:
            notification_executor.submit(
                _send_parent_warning_email_task,
                app_instance,
                mail_func,
                pref.parent_email,
                parent_name,
                student.full_name,
                course.code,
                course.title,
                pct,
                threshold
            )

        # WhatsApp the parent
        if pref.parent_phone:
            send_parent_warning_whatsapp(
                pref.parent_phone,
                parent_name,
                student.full_name,
                course.code,
                pct,
                threshold
            )


def _send_warning_email_task(app_instance, mail_func, email, name, code, title, pct, threshold):
    """Email warning - runs in thread pool."""
    subject = f"⚠️ Attendance Warning — {code}"

    text_body = (
        f"Hello {name},\n\n"
        f"Your attendance for {code} ({title}) is currently at {pct:.0f}%, "
        f"which is below the required {threshold}%.\n\n"
        f"Please ensure you attend upcoming classes to avoid issues.\n\n"
        f"— ScanMark, FUNAAB"
    )

    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#f0f4f0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0"
        style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#dc3545 0%,#c82333 100%);padding:36px 40px;text-align:center;">
            <p style="margin:0 0 8px;font-size:36px;">⚠️</p>
            <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:800;">
              Attendance Warning
            </h1>
            <p style="margin:6px 0 0;color:rgba(255,255,255,0.8);font-size:14px;">
              Your attendance needs attention
            </p>
          </td>
        </tr>

        <!-- Content -->
        <tr>
          <td style="padding:32px 40px;">
            <p style="font-size:16px;color:#1a1a1a;margin:0 0 8px;font-weight:700;">
              Hello {name}! 👋
            </p>
            <p style="font-size:14px;color:#555;margin:0 0 20px;line-height:1.6;">
              Your attendance for <strong>{code} — {title}</strong> has dropped below
              the required threshold.
            </p>

            <!-- Stats -->
            <table width="100%" cellpadding="0" cellspacing="0"
              style="border:1px solid #f5c6cb;border-radius:8px;overflow:hidden;margin-bottom:20px;">
              <tr style="background:#fff5f5;">
                <td style="padding:16px;text-align:center;border-right:1px solid #f5c6cb;">
                  <div style="font-size:28px;font-weight:800;color:#dc3545;">{pct:.0f}%</div>
                  <div style="font-size:11px;color:#999;text-transform:uppercase;letter-spacing:1px;">
                    Your Attendance
                  </div>
                </td>
                <td style="padding:16px;text-align:center;">
                  <div style="font-size:28px;font-weight:800;color:#198754;">{threshold}%</div>
                  <div style="font-size:11px;color:#999;text-transform:uppercase;letter-spacing:1px;">
                    Required Minimum
                  </div>
                </td>
              </tr>
            </table>

            <div style="background:#fff3cd;border-left:4px solid #ffc107;padding:14px 16px;border-radius:4px;">
              <p style="margin:0;font-size:13px;color:#555;line-height:1.5;">
                <strong>💡 Tip:</strong> Attend the next few classes consistently to bring
                your attendance back above the required level.
              </p>
            </div>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:20px 40px;border-top:1px solid #e2e8e2;text-align:center;">
            <p style="margin:0;font-size:12px;color:#999;">
              <strong>Federal University of Agriculture, Abeokuta (FUNAAB)</strong><br/>
              © {datetime.now().year} ScanMark Attendance System
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
    """.strip()

    mail_func(subject, email, text_body, html_body)


def _send_parent_warning_email_task(app_instance, mail_func, parent_email, parent_name, student_name, code, title, pct, threshold):
    """Email warning to parent/guardian — runs in thread pool."""
    subject = f"Parent Alert — {student_name}'s attendance is low ({code})"

    text_body = (
        f"Dear {parent_name},\n\n"
        f"Your ward {student_name}'s attendance for {code} ({title}) "
        f"is currently at {pct:.0f}%, which is below the required {threshold}%.\n\n"
        f"Please encourage them to attend upcoming classes.\n\n"
        f"— ScanMark, FUNAAB"
    )

    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#f0f4f0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0"
        style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
        <tr>
          <td style="background:linear-gradient(135deg,#dc3545 0%,#c82333 100%);padding:36px 40px;text-align:center;">
            <p style="margin:0 0 8px;font-size:36px;">👨‍👩‍👧</p>
            <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:800;">Parent/Guardian Alert</h1>
            <p style="margin:6px 0 0;color:rgba(255,255,255,0.8);font-size:13px;">{student_name}'s attendance needs attention</p>
          </td>
        </tr>
        <tr>
          <td style="padding:32px 40px;">
            <p style="font-size:16px;color:#1a1a1a;margin:0 0 8px;font-weight:700;">Dear {parent_name},</p>
            <p style="font-size:14px;color:#555;margin:0 0 20px;line-height:1.6;">
              Your ward <strong>{student_name}</strong>'s attendance for
              <strong>{code} — {title}</strong> has dropped below the required minimum.
            </p>
            <table width="100%" cellpadding="0" cellspacing="0"
              style="border:1px solid #f5c6cb;border-radius:8px;overflow:hidden;margin-bottom:20px;">
              <tr style="background:#fff5f5;">
                <td style="padding:16px;text-align:center;border-right:1px solid #f5c6cb;">
                  <div style="font-size:28px;font-weight:800;color:#dc3545;">{pct:.0f}%</div>
                  <div style="font-size:11px;color:#999;text-transform:uppercase;letter-spacing:1px;">Current Attendance</div>
                </td>
                <td style="padding:16px;text-align:center;">
                  <div style="font-size:28px;font-weight:800;color:#198754;">{threshold}%</div>
                  <div style="font-size:11px;color:#999;text-transform:uppercase;letter-spacing:1px;">Required Minimum</div>
                </td>
              </tr>
            </table>
            <div style="background:#fff3cd;border-left:4px solid #ffc107;padding:14px 16px;border-radius:4px;">
              <p style="margin:0;font-size:13px;color:#555;line-height:1.5;">
                Please encourage your ward to attend upcoming classes consistently
                to improve their attendance record.
              </p>
            </div>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 40px;border-top:1px solid #e2e8e2;text-align:center;">
            <p style="margin:0;font-size:12px;color:#999;">
              <strong>Federal University of Agriculture, Abeokuta (FUNAAB)</strong><br/>
              &copy; {datetime.now().year} ScanMark Attendance System
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
    """.strip()

    mail_func(subject, parent_email, text_body, html_body)


# ============================================================
# WEEKLY PDF REPORT GENERATION
# ============================================================

# FUNAAB brand colours
FUNAAB_GREEN = colors.HexColor('#006838')
FUNAAB_GREEN_LIGHT = colors.HexColor('#198754')
FUNAAB_GOLD = colors.HexColor('#C8A415')
FUNAAB_BG = colors.HexColor('#f0f4f0')
WHITE = colors.white
BLACK = colors.black


def generate_student_weekly_pdf(student, courses_data, week_start, week_end):
    """
    Generate a styled weekly attendance PDF for a student.

    Args:
        student: User object
        courses_data: list of dicts with keys:
            code, title, total_sessions, attended, percentage
        week_start: datetime
        week_end: datetime

    Returns:
        BytesIO buffer containing the PDF
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=30 * mm,
        bottomMargin=20 * mm,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        title=f"ScanMark Weekly Report — {student.full_name}",
    )

    styles = getSampleStyleSheet()
    elements = []

    # Custom styles
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=22,
        textColor=FUNAAB_GREEN,
        spaceAfter=4,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        textColor=colors.grey,
        alignment=TA_CENTER,
        spaceAfter=20,
    )
    section_style = ParagraphStyle(
        'SectionHead',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=FUNAAB_GREEN,
        spaceBefore=16,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.black,
        leading=14,
    )

    # ── Header ──
    elements.append(Paragraph("🎓 ScanMark Weekly Report", title_style))
    elements.append(Paragraph(
        f"Federal University of Agriculture, Abeokuta",
        subtitle_style
    ))
    elements.append(HRFlowable(
        width="100%", thickness=2, color=FUNAAB_GREEN,
        spaceBefore=2, spaceAfter=12
    ))

    # ── Student Info ──
    elements.append(Paragraph("📋 Student Information", section_style))

    info_data = [
        ['Name', student.full_name],
        ['Matric No', student.matric_no or 'N/A'],
        ['Level', student.level or 'N/A'],
        ['Email', student.email],
        ['Report Period', f"{week_start.strftime('%d %b %Y')} — {week_end.strftime('%d %b %Y')}"],
        ['Generated', datetime.now().strftime('%d %b %Y, %I:%M %p')],
    ]
    info_table = Table(info_data, colWidths=[120, 350])
    info_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), FUNAAB_GREEN),
        ('TEXTCOLOR', (1, 0), (1, -1), BLACK),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#e2e8e2')),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 16))

    # ── Attendance Breakdown ──
    elements.append(Paragraph("📊 Attendance Breakdown", section_style))

    if courses_data:
        header = ['Course Code', 'Title', 'Sessions', 'Attended', 'Rate', 'Status']
        rows = [header]

        for c in courses_data:
            pct = c['percentage']
            status = '✅ Good' if pct >= 75 else '⚠️ Warning' if pct >= 50 else '🚨 Critical'
            rows.append([
                c['code'],
                c['title'][:30],
                str(c['total_sessions']),
                str(c['attended']),
                f"{pct:.0f}%",
                status,
            ])

        att_table = Table(rows, colWidths=[70, 150, 55, 55, 50, 80])
        att_table.setStyle(TableStyle([
            # Header row
            ('BACKGROUND', (0, 0), (-1, 0), FUNAAB_GREEN),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGNMENT', (0, 0), (-1, 0), 'CENTER'),

            # Data rows
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ALIGNMENT', (2, 1), (4, -1), 'CENTER'),

            # Alternating row colours
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, FUNAAB_BG]),

            # Borders
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('LINEBELOW', (0, 0), (-1, 0), 2, FUNAAB_GREEN),

            # Padding
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(att_table)

        # Overall average
        if courses_data:
            avg = sum(c['percentage'] for c in courses_data) / len(courses_data)
            avg_color = '#198754' if avg >= 75 else '#ffc107' if avg >= 50 else '#dc3545'

            elements.append(Spacer(1, 12))
            avg_style = ParagraphStyle(
                'AvgStyle',
                parent=body_style,
                fontSize=13,
                fontName='Helvetica-Bold',
                alignment=TA_CENTER,
            )
            elements.append(Paragraph(
                f'<font color="{avg_color}">Overall Attendance: {avg:.1f}%</font>',
                avg_style
            ))
    else:
        elements.append(Paragraph(
            "No course data available for this period.",
            body_style
        ))

    # ── Footer ──
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(
        width="100%", thickness=1, color=colors.HexColor('#dee2e6'),
        spaceBefore=10, spaceAfter=10
    ))
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        textColor=colors.grey,
        alignment=TA_CENTER,
    )
    elements.append(Paragraph(
        f"© {datetime.now().year} ScanMark · FUNAAB · Automated Weekly Report · Confidential",
        footer_style
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer


def generate_lecturer_weekly_pdf(lecturer, courses_data, week_start, week_end):
    """
    Generate a styled weekly course-summary PDF for a lecturer/coordinator.

    Args:
        lecturer: User object
        courses_data: list of dicts with keys:
            code, title, total_enrolled, avg_attendance_pct, sessions_this_week
        week_start, week_end: datetime

    Returns:
        BytesIO buffer containing the PDF
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=30 * mm,
        bottomMargin=20 * mm,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        title=f"ScanMark Course Report — {lecturer.full_name}",
    )

    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle(
        'LecTitle', fontName='Helvetica-Bold', fontSize=22,
        textColor=FUNAAB_GREEN, spaceAfter=4, alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'LecSubtitle', fontName='Helvetica', fontSize=11,
        textColor=colors.grey, alignment=TA_CENTER, spaceAfter=20
    )
    section_style = ParagraphStyle(
        'LecSection', fontName='Helvetica-Bold', fontSize=14,
        textColor=FUNAAB_GREEN, spaceBefore=16, spaceAfter=8
    )

    # Header
    elements.append(Paragraph("📚 ScanMark Course Report", title_style))
    elements.append(Paragraph("Federal University of Agriculture, Abeokuta", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=FUNAAB_GREEN, spaceBefore=2, spaceAfter=12))

    # Lecturer info
    elements.append(Paragraph("👨‍🏫 Lecturer Information", section_style))

    info_data = [
        ['Name', lecturer.full_name],
        ['Email', lecturer.email],
        ['Department', lecturer.department or 'N/A'],
        ['Report Period', f"{week_start.strftime('%d %b %Y')} — {week_end.strftime('%d %b %Y')}"],
    ]
    info_table = Table(info_data, colWidths=[120, 350])
    info_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), FUNAAB_GREEN),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#e2e8e2')),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 16))

    # Course summary table
    elements.append(Paragraph("📊 Course Summary", section_style))

    if courses_data:
        header = ['Code', 'Title', 'Enrolled', 'Sessions', 'Avg Attendance']
        rows = [header]
        for c in courses_data:
            rows.append([
                c['code'],
                c['title'][:35],
                str(c['total_enrolled']),
                str(c['sessions_this_week']),
                f"{c['avg_attendance_pct']:.0f}%",
            ])

        tbl = Table(rows, colWidths=[70, 170, 60, 60, 90])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), FUNAAB_GREEN),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGNMENT', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ALIGNMENT', (2, 1), (-1, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, FUNAAB_BG]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('LINEBELOW', (0, 0), (-1, 0), 2, FUNAAB_GREEN),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(tbl)
    else:
        elements.append(Paragraph("No courses to report on.", ParagraphStyle('NoData', fontSize=10)))

    # Footer
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#dee2e6')))
    footer = ParagraphStyle('Ft', fontSize=8, textColor=colors.grey, alignment=TA_CENTER)
    elements.append(Paragraph(
        f"© {datetime.now().year} ScanMark · FUNAAB · Weekly Course Report · Confidential",
        footer
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer


def send_weekly_report_email(app_instance, mail_func, recipient_email, recipient_name, pdf_buffer, report_type, week_range_str):
    """
    Send a weekly PDF report via email.

    Args:
        mail_func: the send_email function from app.py
        pdf_buffer: BytesIO with PDF content
        report_type: 'student' or 'lecturer'
    """
    from flask_mail import Message as MailMessage

    subject = f"📊 ScanMark Weekly Report — {week_range_str}"

    text_body = (
        f"Hello {recipient_name},\n\n"
        f"Please find your weekly attendance report attached.\n\n"
        f"Report period: {week_range_str}\n\n"
        f"— ScanMark, FUNAAB"
    )

    html_body = f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f0f4f0;font-family:'Helvetica Neue',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
    <tr><td align="center">
      <table width="560" style="background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
        <tr>
          <td style="background:linear-gradient(135deg,#006838,#198754);padding:30px 40px;text-align:center;border-radius:12px 12px 0 0;">
            <p style="margin:0;font-size:36px;">📊</p>
            <h1 style="margin:8px 0 0;color:#fff;font-size:22px;">Weekly Attendance Report</h1>
            <p style="margin:6px 0 0;color:rgba(255,255,255,0.8);font-size:13px;">{week_range_str}</p>
          </td>
        </tr>
        <tr>
          <td style="padding:28px 40px;">
            <p style="font-size:15px;color:#1a1a1a;font-weight:700;">Hello {recipient_name}! 👋</p>
            <p style="font-size:14px;color:#555;line-height:1.6;">
              Your weekly attendance report is attached to this email as a PDF.
              Open it to see your full attendance breakdown for the week.
            </p>
            <div style="background:#f7faf7;border:1px solid #e2e8e2;border-radius:8px;padding:16px;text-align:center;margin:20px 0;">
              <p style="margin:0;font-size:13px;color:#666;">
                📎 <strong>Attachment:</strong> ScanMark_Report_{week_range_str.replace(' ', '_')}.pdf
              </p>
            </div>
          </td>
        </tr>
        <tr>
          <td style="padding:16px 40px;border-top:1px solid #e2e8e2;text-align:center;">
            <p style="margin:0;font-size:11px;color:#999;">
              © {datetime.now().year} ScanMark · FUNAAB · Automated Report
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
    """.strip()

    def _send(app_inst):
        with app_inst.app_context():
            try:
                from flask_mail import Message as FlaskMessage
                from flask import current_app

                msg = FlaskMessage(
                    subject=subject,
                    recipients=[recipient_email],
                    sender=current_app.config.get('MAIL_DEFAULT_SENDER')
                )
                msg.body = text_body
                msg.html = html_body

                # Attach PDF
                pdf_buffer.seek(0)
                filename = f"ScanMark_Report_{week_range_str.replace(' ', '_').replace('—', 'to')}.pdf"
                msg.attach(
                    filename,
                    'application/pdf',
                    pdf_buffer.read()
                )

                from flask_mail import Mail
                mail = Mail(current_app)
                mail.send(msg)
                print(f"[OK] Weekly report sent to {recipient_email}")
            except Exception as e:
                print(f"[ERROR] Failed to send weekly report to {recipient_email}: {e}")

    notification_executor.submit(_send, app_instance)
