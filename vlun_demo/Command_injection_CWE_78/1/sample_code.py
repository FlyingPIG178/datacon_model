def entry():
    command = input("Enter command: ")
    process(command)

def process(data):
    sanitize(data)
    execute(data)                       

def sanitize(s):
    if ';' in s:
        s = s.replace(';', '')
    return s

def execute(cmd):
    eval(cmd)
