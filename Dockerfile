FROM python:3.9-slim

WORKDIR /app

# Copy dependencies first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories if they don't exist
RUN mkdir -p uploads restricted

# Set permissions
RUN chmod 777 uploads restricted

# Expose the port the app will run on
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"] 