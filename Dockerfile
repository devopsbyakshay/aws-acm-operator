# Use the official Python 3.10 image
FROM python:3.10-alpine
#RUN apt update -y
# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY ./src/ .

CMD python /app/main.py
