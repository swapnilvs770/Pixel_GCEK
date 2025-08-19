# Pixel Club Web Application

This is a Flask-based web application for the Pixel Club. It provides a platform for administrative functions, user management, event permissions, and a photo gallery.

## Features

- **Admin Dashboard**: Manage user accounts and review event requests.
- **User Authentication**: Secure login for both administrators and regular users using hashed passwords.
- **Event Management**: Submit and manage event coverage requests with a multi-level approval system (Pixel Member, Pixel Head, Faculty Advisor).
- **PDF Generation**: Automatically generates and emails official approval letters in PDF format for approved events.
- **Image Gallery**: A dynamic gallery to showcase club photos.

## Prerequisites

Before running the application, you need to have the following installed:

- Python 3.x
- MySQL Database

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/your-repository-name.git](https://github.com/your-username/your-repository-name.git)
    cd your-repository-name
    ```

2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Database Setup:**
    The application connects to a MySQL database.
    -   Create a database named `pixel_db`.
    -   You will need to create the `login` and `permission_requests` tables with the appropriate columns as defined in the `app.py` file.

5.  **Environment Variables:**
    Create a `.env` file in the project's root directory and add the following configuration:

    ```ini
    APP_SECRET_KEY='a_strong_random_secret_key'
    MYSQL_HOST='localhost'
    MYSQL_USER='root'
    MYSQL_PASSWORD=''
    MYSQL_DATABASE='pixel_db'
    SMTP_SERVER='smtp.gmail.com'
    SMTP_PORT=465
    SENDER_EMAIL='your_email@gmail.com'
    SENDER_PASSWORD='your_app_password'
    ```

    * `APP_SECRET_KEY`: A secret key for Flask sessions.
    * `MYSQL_*`: Your database credentials.
    * `SMTP_*`: Your email server details for sending notifications and passwords. For Gmail, you need to use a [Google App Password](https://support.google.com/accounts/answer/185833).

6.  **Run the application:**
    ```bash
    flask run
    ```
    The application will be available at `http://127.0.0.1:5000`.