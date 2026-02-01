# Use an official Node runtime as a parent image
FROM node:20-alpine

# Install build tools required for better-sqlite3 on Alpine
RUN apk add --no-cache python3 make g++

# Set the working directory to /app (standard convention)
WORKDIR /app

# Create directories for SSL certificates and data
RUN mkdir -p /app/ssl /app/data

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Start the app using the script defined in package.json
CMD ["npm", "run", "start"]