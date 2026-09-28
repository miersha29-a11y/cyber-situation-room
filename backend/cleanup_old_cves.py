import sqlite3

connection = sqlite3.connect("cyber_situation_room.db")
cursor = connection.cursor()

# Keep only CVEs published in 2026
cursor.execute(
    "DELETE FROM cves WHERE published_date NOT LIKE ?",
    ("2026-%",)
)

connection.commit()

remaining = cursor.execute(
    "SELECT COUNT(*) FROM cves"
).fetchone()[0]

print(f"Old CVEs removed.")
print(f"Remaining CVEs: {remaining}")

connection.close()