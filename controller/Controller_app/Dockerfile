# Use python 3.12 as the base image
FROM python:3.12

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file .. it containes all the dependencies for the python application
COPY requirements.txt .

# Install all our dependencies from the requirements.txt file
RUN pip install -r requirements.txt

# Copy everything from the current folder to /app
COPY . .

# Run the application
CMD ["python", "src/controller.py"]