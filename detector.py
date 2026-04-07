def is_malicious(input_text):
    patterns = [
        "' OR '1'='1",
        "--",
        "DROP TABLE",
        "SELECT *",
        "INSERT INTO",
        "DELETE FROM"
    ]

    input_upper = input_text.upper()

    for pattern in patterns:
        if pattern in input_upper:
            return True

    return False