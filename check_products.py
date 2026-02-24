import sqlite3


conn = sqlite3.connect("smartcart.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM products")

rows = cursor.fetchall()

print("Number of products:", len(rows))

for row in rows[:5]:
    print(row)

conn.close()