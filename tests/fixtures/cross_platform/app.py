CONFIG_PATH = "/etc/myapp/config.yaml"


def load():
    with open(CONFIG_PATH) as fh:
        return fh.read()
