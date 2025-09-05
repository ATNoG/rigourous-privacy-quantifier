FROM python:3.12-slim

# set working directory
WORKDIR /app

# install system dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends

# copy requirements and install Python packages
COPY . .

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

CMD ["sh", "-c", "python3 main.py"]
