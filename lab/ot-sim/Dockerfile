FROM python:3.11-slim
RUN pip install --no-cache-dir "pymodbus==3.6.9" "python-snap7==1.3"
WORKDIR /app
COPY sim.py dnp3_cold_restart.py ./
EXPOSE 102 502 20000 55553 55555
CMD ["python", "-u", "sim.py"]
