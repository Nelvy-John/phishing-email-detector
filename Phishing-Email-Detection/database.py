import mysql.connector
from mysql.connector import Error

def get_connection():
    """Create a database connection ensuring safe handling."""
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="your_username",
            password="your_password",
            database="phishing_db"
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error while connecting to MySQL: {e}")
        return None

def save_log(email, result, confidence):
    """Save the extraction results to the database safely."""
    conn = get_connection()
    if conn is None:
        print("Failed to connect to database. Log not saved.")
        return

    cur = None
    try:
        cur = conn.cursor()
        query = """
        INSERT INTO prediction_logs(email_text, result, confidence)
        VALUES(%s, %s, %s)
        """
        cur.execute(query, (email, result, confidence))
        conn.commit()
        print("Log saved successfully")
        
    except Error as e:
        print(f"Error while saving log: {e}")
        
    finally:
        if conn and conn.is_connected():
            if cur:
                cur.close()
            conn.close()
            # print("MySQL connection is closed")

if __name__ == "__main__":
    print("Testing database connection...")
    conn = get_connection()
    if conn:
        print("[SUCCESS] Database connection successful!")
        conn.close()
    else:
        print("[FAILED] Database connection failed.")
        print("Ensure 'phishing_db' exists. You can run setup_db.py to create it.")
