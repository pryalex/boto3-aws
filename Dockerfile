FROM python:3.11.2

WORKDIR /boto
COPY main.py /boto/main.py
COPY requirements.txt /boto/requirements.txt
RUN pip install -r /boto/requirements.txt

CMD ["python", "main.py"]