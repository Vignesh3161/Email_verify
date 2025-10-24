import redis, json, smtplib, socket
from validate_email_address import validate_email

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

def verify_smtp(email):
    try:
        is_valid = validate_email(email, verify=True)
        if is_valid:
            return {"email": email, "result": True}
        else:
            return {"email": email, "result": "smtp"}
    except (socket.error, smtplib.SMTPException):
        return {"email": email, "result": "smtp"}

if __name__ == "__main__":
    print("SMTP worker started...")
    while True:
        _, task = r.blpop("smtp-verification")
        data = json.loads(task)
        result = verify_smtp(data['email'])
        r.rpush("verification-results", json.dumps(result))
