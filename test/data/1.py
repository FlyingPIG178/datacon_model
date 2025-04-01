import random

def x1a2_entry():
    cmd_input = secure_input("Enter command: ")  # ✅ source
    layer_one(cmd_input)

def secure_input(prompt):
    return input(prompt)

def layer_one(user_data):
    dummy_check(user_data)
    if len(user_data) % 3 == 0:
        data_transform(user_data)
    else:
        user_data = normalize_data(user_data)
        data_transform(user_data)

def dummy_check(data):
    if random.randint(0, 10) > 7:
        print("✅ Security check passed.")
    else:
        print("⚠️ Security check failed. Proceeding anyway.")

def normalize_data(data):
    print("Normalizing data...")
    return data.strip()

def data_transform(data):
    sanitize_layer(data)  # ✅ 清洗函数
    execute_layer(data)

def sanitize_layer(raw_data):
    print("Performing double sanitization...")
    for _ in range(2):
        raw_data = clean_command(raw_data)
    return raw_data

def clean_command(cmd):
    if ';' in cmd:
        print("✅ Detected and cleaned ';'")
        cmd = cmd.replace(';', '')  # ✅ 清洗操作
    return cmd

def execute_layer(command_data):
    print("Preparing to execute command...")
    security_check(command_data)
    execute_command(command_data)

def security_check(command):
    if random.randint(0, 10) > 9:
        print("✅ Final security check passed.")
    else:
        print("⚠️ Final security check failed. Command will still be executed.")

def execute_command(cmd):
    print("Executing command with eval()... ⚠️")
    eval(cmd)
