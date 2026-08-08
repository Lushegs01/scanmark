import os


# Set before test modules import the application. Tests never touch a developer
# database or start the weekly scheduler/outbound notification path.
os.environ.setdefault('DATABASE_URL', 'sqlite:///:memory:')
os.environ.setdefault('SECRET_KEY', 'scanmark-test-secret')
os.environ.setdefault('SCANMARK_DISABLE_SCHEDULER', '1')
os.environ.setdefault('SCAN_CONFIRMATION_EMAILS', 'false')
