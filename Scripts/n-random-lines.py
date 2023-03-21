import random
import sqlite3

size = 10000
sample_ids = []
sample_sha256 = []
samples_len = 0

conn = sqlite3.connect("/home/kali/Downloads/mlaware/meta.db")
cursor = conn.cursor()
cursor.execute("""SELECT sha256 FROM meta WHERE is_malware >= 1""")
result = cursor.fetchall()

for row in result:
    sample_sha256.append(row[0])

samples_len = len(sample_sha256)

i = 0
while i < size:
    r = random.SystemRandom().randint(0, samples_len - 1)
    if not r in sample_ids:
        sample_ids.append(r)
        i += 1

print("Shuffle done")

f = open("samples.txt", "w")
for index in sample_ids:
    f.write(f"{sample_sha256[index]}\n")

f.close()
print("Hashes written")