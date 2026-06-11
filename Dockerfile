# Copilot SOC — Python 3.12 slim base (3.14 has litellm compat issues with cgi module)
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "copilot_soc.main:app", "--host", "0.0.0.0", "--port", "8000"]
