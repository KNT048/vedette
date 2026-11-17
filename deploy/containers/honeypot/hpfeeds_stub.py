# Stands in for hpfeeds (GPL-3), which OpenCanary imports at the top of logger.py but calls only for an hpfeeds logger.
def new(*a, **k):
    raise RuntimeError("hpfeeds is not shipped")
