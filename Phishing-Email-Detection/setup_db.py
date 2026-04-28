import mysql.connector
from mysql.connector import Error

def create_database():
    try:
        # Connect to MySQL server (no database selected yet)
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root"
        )
        if conn.is_connected():
            cursor = conn.cursor()
            
            # Create database
            cursor.execute("CREATE DATABASE IF NOT EXISTS phishing_db")
            print("Database 'phishing_db' created or already exists.")
            
            # Connect to the new database
            conn.database = "phishing_db"
            
            # Create table
            query = """
            CREATE TABLE IF NOT EXISTS logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email TEXT,
                result VARCHAR(255),
                confidence FLOAT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
            cursor.execute(query)
            print("Table 'logs' created or already exists.")
            
    except Error as e:
        print(f"Error: {e}")
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn.is_connected():
            conn.close()

if __name__ == "__main__":
    create_database()
