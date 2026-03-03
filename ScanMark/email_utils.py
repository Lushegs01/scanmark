from flask_mail import Message
from flask import render_template, current_app
from threading import Thread

def send_async_email(app, msg):
    """Send email asynchronously to avoid blocking"""
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            current_app.logger.error(f"Failed to send email: {str(e)}")

def send_email(subject, recipients, text_body, html_body, sender=None):
    """
    Send email with both text and HTML versions
    
    Args:
        subject: Email subject
        recipients: List of recipient email addresses
        text_body: Plain text version
        html_body: HTML version
        sender: Optional sender email (uses default if not provided)
    """
    from app import mail, app  # Import here to avoid circular imports
    
    msg = Message(
        subject=subject,
        recipients=recipients if isinstance(recipients, list) else [recipients],
        sender=sender or current_app.config['MAIL_DEFAULT_SENDER']
    )
    msg.body = text_body
    msg.html = html_body
    
    # Send asynchronously
    Thread(target=send_async_email, args=(app, msg)).start()

def send_welcome_email(user_email, user_name):
    """Send welcome email to new user"""
    subject = "Welcome to Attendance System!"
    
    # Plain text version
    text_body = f"""
    Hello {user_name},

    Welcome to the Attendance Management System!

    Your account has been successfully created. You can now:
    - Mark attendance by scanning QR codes
    - View your attendance history
    - Track your course participation

    If you have any questions, please don't hesitate to contact support.

    Best regards,
    Attendance System Team
    """
    
    # HTML version
    html_body = render_template('emails/welcome.html', 
                               user_name=user_name)
    
    send_email(subject, user_email, text_body, html_body)

def send_attendance_confirmation(user_email, user_name, course_code, course_title, timestamp):
    """Send email when attendance is marked"""
    subject = f"Attendance Confirmed - {course_code}"
    
    text_body = f"""
    Hello {user_name},

    Your attendance has been successfully recorded:
    
    Course: {course_code} - {course_title}
    Time: {timestamp}
    
    Best regards,
    Attendance System Team
    """
    
    html_body = render_template('emails/attendance_confirmation.html',
                               user_name=user_name,
                               course_code=course_code,
                               course_title=course_title,
                               timestamp=timestamp)
    
    send_email(subject, user_email, text_body, html_body)