FROM python:3.11.2
RUN pip install -r requirements.txt
COPY main.py main.py

CMD ["python", "main.py"]