FROM python:3.9
COPY requirements.txt /
RUN pip3 install -r requirements.txt
COPY templates /templates
COPY main.py /

ENTRYPOINT ["gunicorn", "main:app", "-w", "2", "--threads", "2", "-b", "0.0.0.0:8000"]
