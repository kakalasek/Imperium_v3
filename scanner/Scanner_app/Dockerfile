# Use python 3.12 as the base image
FROM python:3.12

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file .. it containes dependencies for the python application
COPY requirements.txt .

# Install all our dependencies from the requirements.txt file
RUN pip install -r requirements.txt

# Run apt update
RUN apt update

# Install Nmap
RUN apt -y install nmap=7.93+dfsg1-1

# Copy everything from the current folder to /app
COPY . .

CMD ["python", "src/scanner.py"]