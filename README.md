Features
Task Management:

Create, update, and delete tasks.

Drag-and-drop functionality to move tasks between columns.

Retrieve all tasks.

User Authentication:
User registration and login.
Google login authentication.
RESTful API:
CRUD (Create, Read, Update, Delete) operations for tasks.
Authentication routes for user registration, login, and Google login.
Technologies Used
Frontend:
React
Tailwind CSS
Axios
Backend:
Node.js

Express.js

Prisma ORM

PostgreSQL

Zod for validation

Google Auth

JWT for authentication

Getting Started

Prerequisites

Node.js

PostgreSQL

A Google Cloud Platform account for Google Auth setup

Setup Project
Frontend
cd /frontend

npm i

Create a .env file in the root directory and add the following variables: VITE_GOOGLE_CLIENT_ID

npm run dev

Backend
-cd /backend

npm i

Set up environment variables:

Create a .env file in the root directory and add the following variables: DATABASE_URL=your_database_url JWT_SECRET=your_jwt_secret GOOGLE_CLIENT_ID=your_google_client_id GOOGLE_CLIENT_SECRET=your_google_client_secret

npx prisma migrate dev

node index.js
