import ftplib
import hashlib
import io
import ssl
import sys

port, node, directory = int(sys.argv[1]), sys.argv[2], sys.argv[3]
plain = ftplib.FTP()
plain.connect("127.0.0.1", port, timeout=20)
try:
    plain.login("admin", "ftp-test-password")
    raise AssertionError("Plaintext authentication was accepted")
except ftplib.error_perm as error:
    assert str(error).startswith("534"), error
plain.close()

context = ssl._create_unverified_context()  # Isolated generated test certificate.
ftp = ftplib.FTP_TLS(context=context)
ftp.connect("127.0.0.1", port, timeout=30)
ftp.auth()
try:
    ftp.login("admin", "wrong")
    raise AssertionError("Wrong password accepted")
except ftplib.error_perm:
    pass
ftp.login("admin", "ftp-test-password")
try:
    ftp.prot_c()
    raise AssertionError("Clear data protection was accepted")
except ftplib.error_perm:
    pass
ftp.prot_p()
assert ftp.sendcmd("EPSV").startswith("229")
assert node in ftp.nlst(), "Virtual node directory missing"
ftp.cwd("/" + node)
assert directory.split("/")[1] in ftp.nlst(), "Node filesystem root missing"
ftp.cwd("/" + node + directory)
assert directory in ftp.pwd()
ftp.mkd("Каталог проверки")
ftp.cwd("Каталог проверки")
data = bytes(range(256)) * 12001
ftp.storbinary("STOR тест.bin", io.BytesIO(data))
items = dict(ftp.mlsd())
assert int(items["тест.bin"]["size"]) == len(data)
received = io.BytesIO()
ftp.retrbinary("RETR тест.bin", received.write)
assert hashlib.sha256(received.getvalue()).digest() == hashlib.sha256(data).digest()
received = io.BytesIO()
ftp.retrbinary("RETR тест.bin", received.write, rest=12345)
assert received.getvalue() == data[12345:]
ftp.storbinary("STOR тест.bin", io.BytesIO(b"replacement"), rest=123)
received = io.BytesIO()
ftp.retrbinary("RETR тест.bin", received.write)
assert received.getvalue() == data[:123] + b"replacement"
ftp.rename("тест.bin", "renamed.bin")
assert ftp.size("renamed.bin") == 134
ftp.delete("renamed.bin")
ftp.cwd("..")
ftp.rmd("Каталог проверки")
try:
    ftp.sendcmd("PORT 127,0,0,1,1,1")
    raise AssertionError("FTP bounce/active mode accepted")
except ftplib.error_perm:
    pass
ftp.quit()
print("PASS: Python ftplib.FTP_TLS interoperates through a routed PNT endpoint.")
