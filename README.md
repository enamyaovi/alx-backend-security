# IP Tracking and Security Middleware Project

## Overview

This Django project implements request logging, IP blocking, geolocation tracking, rate limiting, and anomaly detection for sensitive paths such as `/login` and `/admin`.

It is designed to enhance application security by monitoring request patterns and preventing abuse.

## Features

* **IP Logging**: Logs every incoming request with IP address, path, timestamp, country, and city.
* **Geolocation**: Uses `django-ip-geolocation` middleware to attach geolocation data to requests and caches results in Redis for 24 hours.
* **IP Blocking**: Supports blacklisting IPs via `BlockedIP` model and a management command (`block_ip`) to block/unblock IPs.
* **Sensitive Path Tracking**: Counts requests to sensitive paths using Redis and flags excessive access.
* **Rate Limiting**: Implements per-user and per-IP request limits using `django-ratelimit`.
* **Anomaly Detection**: Celery task identifies suspicious IPs exceeding a configurable request threshold.

## Project Structure

```
ip_tracking/
├── middleware.py       # Logs requests, counts sensitive path hits, handles geolocation and blocking
├── models.py           # Defines RequestLog, BlockedIP, and SuspiciousIP
├── tasks.py            # Celery tasks for logging and anomaly detection
├── management/commands/
│   └── block_ip.py     # Management command to block/unblock IPs
└── views.py            # Sample views with rate limiting
```

## Installation

1. Clone the repository.
2. Create and activate a virtual environment.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Set environment variables for Django settings and geolocation API keys. Example `.env`:

```
ALLOWED_HOSTS=*
DEBUG=True
SECRET_KEY=not-a-secret-key-111-222-333
IP_API_USERNAME=someusername
IP_API_KEY=yourapikey
```

5. Apply migrations:

```bash
django manage.py migrate
```

## Configuration

* **Environment Variables**: Uses `django-environ` to manage secrets, allowed hosts, debug mode, and IP geolocation API credentials.
* **Middleware**: Add `IpGeolocationMiddleware` and `IPLoggingMiddleware` in `settings.py`.
* **Cache**: Configure Redis in `CACHES` for sensitive path counting and geolocation caching.
* **Rate Limiting**: Configure `django-ratelimit` decorators in views and set `RATELIMIT_USE_CACHE` to Redis.
* **Celery**:

```python
CELERY_BROKER_URL = 'redis://127.0.0.1:6379/1'
CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379/2'
CELERY_BEAT_SCHEDULE = {
    'detect-anomalies-hourly': {
        'task': 'ip_tracking.tasks.detect_anomalies',
        'schedule': crontab(minute=0, hour='*'),
    },
}
```

## Usage

* Run the Django server:

```bash
django manage.py runserver
```

* Block/unblock IPs:

```bash
django manage.py block_ip --block 192.168.1.1
django manage.py block_ip --unblock 192.168.1.1
```

* Celery worker and beat for anomaly detection:

```bash
celery -A alx_backend_security worker -l info
celery -A alx_backend_security beat -l info
```

## Notes

* Users must obtain an API key from the geolocation service (e.g., IPStack) and set `IP_API_USERNAME` and `IP_API_KEY` in the `.env` file.
* Sensitive path hits are counted in Redis to avoid DB overhead.
* Geolocation results are cached for 24 hours.
* Anomaly detection flags IPs exceeding request thresholds and stores them in `SuspiciousIP`.
* Rate limiting protects critical views from brute-force attacks.

## License

MIT License
