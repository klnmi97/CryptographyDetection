import os
import sqlite3

# Counters
total_files = 0
packed_files = 0

# Set up database connection
conn = sqlite3.connect("/home/kali/Downloads/mlaware/meta.db")
cursor = conn.cursor()

# Get list of files in directory
dir_path = '/home/kali/Documents/Samples/malware'
files = os.listdir(dir_path)

# Loop through files and query database
for file_name in files:
    total_files += 1
    # Construct SQL query using file name
    query = f'SELECT packed FROM meta WHERE sha256="{file_name}"'
    cursor.execute(query)

    # Process query results
    result = cursor.fetchone()
    if result[0] > 0:
        packed_files += 1

# Close database connection
conn.close()

print(f"Total files: {total_files}, packed files: {packed_files}, which is {packed_files / total_files * 100}")