FROM node:24-alpine AS frontend

WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend ./
RUN npm run build

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv/app

COPY pyproject.toml README.md hatch_build.py ./
COPY backend ./backend
COPY ml ./ml
COPY --from=frontend /ui/dist ./backend/app/static

RUN python -m pip install --no-cache-dir .

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000"]
